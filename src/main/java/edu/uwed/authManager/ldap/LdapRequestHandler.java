package edu.uwed.authManager.ldap;

import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.ldap.protocol.*;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.ByteStringBuffer;
import edu.uwed.authManager.configuration.ConfigProperties;
import edu.uwed.authManager.services.LdapService;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.LdapTemplate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public class LdapRequestHandler extends SimpleChannelInboundHandler<ByteBuf> {

    private final ConfigProperties configProperties;
    private final LdapService ldapService;
    private final SslContext proxySslContext;
    private final SSLContext startTlsSslContext;

    private final ConcurrentHashMap<String, Channel> channelMap = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Object> locks = new ConcurrentHashMap<>();

    private static final Logger logger = LoggerFactory.getLogger(LdapRequestHandler.class);

    // Константы для типов сообщений LDAP

    public LdapRequestHandler(
            ConfigProperties configProperties,
            LdapService ldapService,
            SslContext proxyLDAPSContext,
            SSLContext proxyStartTLSContext
    ) {
        this.configProperties = configProperties;
        this.ldapService = ldapService;
        this.proxySslContext = proxyLDAPSContext;
        this.startTlsSslContext = proxyStartTLSContext;
    }

    // send our response to client's StartTLS that we agree to use secured LDAP with TLS
    private void sendStartTlsResponse(ChannelHandlerContext ctx, int messageId) {
        logger.debug("Sending StartTLS response");
        ExtendedResponseProtocolOp responseOp = new ExtendedResponseProtocolOp(
            new LDAPResult(messageId, ResultCode.SUCCESS)
        );
        LDAPMessage responseMessage = new LDAPMessage(messageId, responseOp);
        ByteStringBuffer buffer = new ByteStringBuffer();
        responseMessage.encode().encodeTo(buffer);
        byte[] responseBytes = buffer.toByteArray();

        ByteBuf responseBuf = ctx.alloc().buffer();
        responseBuf.writeBytes(responseBytes);
        ctx.writeAndFlush(responseBuf).addListener(future -> {
            if (future.isSuccess()) {
                logger.debug("StartTLS response sent successfully");
            } else {
                logger.error("Failed to send StartTLS response", future.cause());
                ctx.close();
            }
        });
    }

    // for incoming LDAP connections
    private void handleStartTls(ChannelHandlerContext ctx, int messageId) throws Exception {
        ConfigProperties.ProxyConfig proxyConfig = configProperties.getProxyConfig();
        logger.debug("Handling StartTLS request");
        sendStartTlsResponse(ctx, messageId); // tell cleint that we agtee to use TLS secured LDAP

        logger.debug("Adding SslHandler with Java SSLContext for StartTLS");
        SSLEngine sslEngine = startTlsSslContext.createSSLEngine(); // verified certs => engine
        sslEngine.setUseClientMode(false); // we are a server
        sslEngine.setNeedClientAuth(proxyConfig != null && proxyConfig.isNeedClientAuth());

        // Проверяем настройки sslProtocols в ProxyConfig
        String sslProtocols = proxyConfig != null ? proxyConfig.getSslProtocols() : null;
        if (sslProtocols != null && !sslProtocols.isEmpty()) {
            String[] protocols = sslProtocols.split(",");
            sslEngine.setEnabledProtocols(protocols);
            logger.debug("Applied protocols from proxy config for StartTLS: {}", Arrays.toString(protocols));
        } else {
            // Дефолтное значение, если конфигурации нет
            String[] defaultProtocols = {"TLSv1.3", "TLSv1.2"};
            sslEngine.setEnabledProtocols(defaultProtocols);
            logger.debug("No sslProtocols in proxy config, using default: {}", Arrays.toString(defaultProtocols));
        }

        SslHandler sslHandler = new SslHandler(sslEngine); // tuned engine => network SSL handler
        sslHandler.setHandshakeTimeout(30000, TimeUnit.MILLISECONDS);
        ctx.pipeline().addFirst("ssl", sslHandler);

        sslHandler.handshakeFuture().addListener(future -> {
            if (future.isSuccess()) {
                logger.debug("TLS handshake completed successfully with cipher: {}", sslHandler.engine().getSession().getCipherSuite());
                logger.info("StartTLS established with client");
            } else {
                logger.error("TLS handshake failed", future.cause());
                ctx.close();
            }
        });
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, ByteBuf msg) throws Exception {
        if (!checkMessageSize(msg)) {
            logger.error("Message size check failed, closing connection");
            ctx.close();
            return;
        }

        logger.debug("Received message with {} bytes on pipeline: {}", msg.readableBytes(), ctx.pipeline().names());
        TargetServerInfo targetInfo = negotiateTargetServer(ctx, msg);
        String target = targetInfo.getTarget();
        logger.debug("Negotiated target server: {}", target);

        if (target != null) {
            ConfigProperties.LdapServerConfig config = configProperties.getLdapServerConfigs().get(target);
            if (config == null) {
                logger.error("No configuration found for target server: {}", target);
                ctx.close();
                return;
            }

            // Проверяем подключение к целевому серверу через LdapService
            boolean connected = ldapService.testConnection(target);
            if (!connected) {
                logger.error("Failed to connect to target server: {}", target);
                ctx.close();
                return;
            }

            // Используем данные из TargetServerInfo
            int messageType = targetInfo.getMessageType();
            int messageId = targetInfo.getMessageId();

            if (messageType == LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST) {
                logger.debug("Received BindRequest with messageId: {}", messageId);
                BindRequestProtocolOp bindOp = targetInfo.getLdapMessage().getBindRequestProtocolOp();
                String bindDn = bindOp.getBindDN();
                byte[] passwordBytes = bindOp.getSimplePassword().getValue();
                String password = passwordBytes != null ? new String(passwordBytes) : "";

                // Выполняем привязку через LdapService
                boolean bindSuccess = ldapService.bind(target, bindDn, password);
                if (bindSuccess) {
                    logger.info("Bind successful for DN: {}", bindDn);
                    sendBindResponse(ctx, messageId, 0); // resultCode=0 (success)
                } else {
                    logger.error("Bind failed for DN: {}", bindDn);
                    sendBindResponse(ctx, messageId, 49); // resultCode=49 (invalidCredentials)
                }
            } else if (messageType == LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST) {
                logger.debug("Received SearchRequest with messageId: {}", messageId);
                SearchRequestProtocolOp searchOp = targetInfo.getLdapMessage().getSearchRequestProtocolOp();
                String baseDn = searchOp.getBaseDN();
                String filter = searchOp.getFilter().toString();

                // Выполняем поиск через LdapService
                List<DirContextOperations> results = ldapService.search(target, baseDn, filter);
                if (results.isEmpty()) {
                    logger.debug("No results found for filter: {}", filter);
                } else {
                    logger.debug("Found {} results for filter: {}", results.size(), filter);
                    // Здесь можно отправить SearchResultEntry для каждой записи
                    // Для примера отправим только SearchResultDone
                }
                sendSearchResponse(ctx, messageId);
            } else {
                logger.warn("Unsupported LDAP operation: type={}", messageType);
                ctx.close();
            }
        }
    }

     private boolean checkMessageSize(ByteBuf msg) {
        int maxMessageSize = configProperties.getProxyConfig().getMaxMessageSize();
        if (msg.readableBytes() > maxMessageSize) {
            logger.error("Message size exceeds maximum allowed: " + msg.readableBytes() + " > " + maxMessageSize);
            return false;
        }
        return true;
    }

    private TargetServerInfo negotiateTargetServer(ChannelHandlerContext ctx, ByteBuf msg) {
        try {
            byte[] bytes = new byte[msg.readableBytes()];
            msg.getBytes(msg.readerIndex(), bytes);
            ASN1StreamReader asn1Reader = new ASN1StreamReader(new ByteArrayInputStream(bytes));
            LDAPMessage ldapMessage = LDAPMessage.readFrom(asn1Reader, true);
            int messageType = ldapMessage.getProtocolOpType();
            int messageId = ldapMessage.getMessageID();
            logger.debug("LDAP message type: {} on pipeline: {}", messageType, ctx.pipeline().names());

            if (messageType == LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST) {
                ExtendedRequestProtocolOp extendedOp = ldapMessage.getExtendedRequestProtocolOp();
                if (LdapConstants.START_TLS_OID.equals(extendedOp.getOID())) {
                    logger.info("Received StartTLS request from client");
                    handleStartTls(ctx, messageId);
                    return new TargetServerInfo(null, ldapMessage, messageType, messageId);
                }
            } else if (messageType == LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST) {
                SearchRequestProtocolOp searchOp = ldapMessage.getSearchRequestProtocolOp();
                String dn = searchOp.getBaseDN();
                logger.debug("Search request DN: {}", dn);
                for (Map.Entry<String, ConfigProperties.LdapServerConfig> entry : configProperties.getLdapServerConfigs().entrySet()) {
                    if (dn.equals(entry.getValue().getVirtualDn())) {
                        return new TargetServerInfo(entry.getKey(), ldapMessage, messageType, messageId);
                    }
                }
                logger.warn("No remote LDAP server found for DN: {}", dn);
                return new TargetServerInfo("dc-01", ldapMessage, messageType, messageId);
            } else if (messageType == LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST) {
                String dn = ldapMessage.getBindRequestProtocolOp().getBindDN();
                logger.debug("Bind request DN: {}", dn);
                for (Map.Entry<String, ConfigProperties.LdapServerConfig> entry : configProperties.getLdapServerConfigs().entrySet()) {
                    if (dn.equals(entry.getValue().getVirtualDn())) {
                        return new TargetServerInfo(entry.getKey(), ldapMessage, messageType, messageId);
                    }
                }
                logger.warn("No remote LDAP server found for bind DN: {}", dn);
                return new TargetServerInfo("dc-01", ldapMessage, messageType, messageId);
            }
            logger.debug("Unhandled message type: {}", messageType);
            return new TargetServerInfo("dc-01", ldapMessage, messageType, messageId);
        } catch (Exception e) {
            logger.error("Failed to parse LDAP request", e);
            return new TargetServerInfo("dc-01", null, -1, -1);
        }
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        logger.info("Client connected: {}", ctx.channel().remoteAddress());
        // Ничего не подключаем, ждём первого запроса
    }

    private void sendBindResponse(ChannelHandlerContext ctx, int messageId, int resultCode) {
        ByteBuf response = Unpooled.buffer();
        response.writeByte(0x30); // SEQUENCE
        response.writeByte(0x0C); // Length of LDAPMessage
        response.writeByte(0x02); // INTEGER (messageID)
        response.writeByte(0x01); // Length of messageID
        response.writeByte(messageId); // messageID
        response.writeByte(0x61); // BindResponse
        response.writeByte(0x07); // Length of BindResponse
        response.writeByte(0x0A); // resultCode (ENUMERATED)
        response.writeByte(0x01); // Length of resultCode
        response.writeByte(resultCode); // resultCode
        response.writeByte(0x81); // matchedDN (optional, empty)
        response.writeByte(0x00); // Length of matchedDN
        response.writeByte(0x82); // diagnosticMessage (optional, empty)
        response.writeByte(0x00); // Length of diagnosticMessage
        ctx.writeAndFlush(response);
    }

    private void sendSearchResponse(ChannelHandlerContext ctx, int messageId) {
        // Заглушка для SearchResponse (SearchResultDone)
        ByteBuf response = Unpooled.buffer();
        response.writeByte(0x30); // SEQUENCE
        response.writeByte(0x0A); // Length of LDAPMessage
        response.writeByte(0x02); // INTEGER (messageID)
        response.writeByte(0x01); // Length of messageID
        response.writeByte(messageId); // messageID
        response.writeByte(0x65); // SearchResultDone
        response.writeByte(0x05); // Length of SearchResultDone
        response.writeByte(0x0A); // resultCode (ENUMERATED)
        response.writeByte(0x01); // Length of resultCode
        response.writeByte(0x00); // success (0)
        response.writeByte(0x81); // matchedDN (optional, empty)
        response.writeByte(0x00); // Length of matchedDN
        ctx.writeAndFlush(response);
    }

//    @Override
//    public void channelInactive(ChannelHandlerContext ctx) {
//        logger.info("Client disconnected: {}", ctx.channel().remoteAddress());
//        outboundChannels.values().forEach(channel -> {
//            if (channel.isActive()) {
//                channel.close();
//            }
//        });
//        outboundChannels.clear();
//    }

//    @Override
//    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
//        logger.error("Error in LDAP request handling", cause);
//        ctx.close();
//    }
}
