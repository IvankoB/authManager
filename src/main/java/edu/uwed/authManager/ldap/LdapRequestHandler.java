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
    private final Map<String, LdapTemplate> ldapTemplates;
    private final Map<String, SslContext> proxySslContexts;
    private final Map<String, SSLContext> outgoingSslContexts;

    private final ConcurrentHashMap<String, Channel> channelMap = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Object> locks = new ConcurrentHashMap<>();

    private static final Logger logger = LoggerFactory.getLogger(LdapRequestHandler.class);

    public LdapRequestHandler(
            ConfigProperties configProperties,
            LdapService ldapService,
            SslContext proxyLDAPSContext,
            SSLContext proxyStartTLSContext,
            @Qualifier("outboundLdapTemplates") Map<String, LdapTemplate> ldapTemplates,
            @Qualifier("outboundSslContexts") Map<String, SslContext> proxySslContexts,
            @Qualifier("outboundSSLContexts") Map<String, SSLContext> outgoingSslContexts
    ) {
        this.configProperties = configProperties;
        this.ldapService = ldapService;
        this.proxySslContext = proxyLDAPSContext;
        this.startTlsSslContext = proxyStartTLSContext;
        this.ldapTemplates = ldapTemplates;
        this.proxySslContexts = proxySslContexts;
        this.outgoingSslContexts = outgoingSslContexts;
    }

    private void sendStartTlsResponse(ChannelHandlerContext ctx, int messageId) {
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

    private void handleStartTls(ChannelHandlerContext ctx, int messageId) throws Exception {
        ConfigProperties.ProxyConfig proxyConfig = configProperties.getProxyConfig();
        if (!proxyConfig.isStartTls()) {
            logger.warn("StartTLS is not enabled in proxy configuration");
            ctx.close();
            return;
        }

        sendStartTlsResponse(ctx, messageId);

        SSLEngine sslEngine = startTlsSslContext.createSSLEngine();
        sslEngine.setUseClientMode(false);
        sslEngine.setNeedClientAuth(proxyConfig.isNeedClientAuth());

        String sslProtocols = proxyConfig.getSslProtocols();
        if (sslProtocols != null && !sslProtocols.isEmpty()) {
            String[] protocols = sslProtocols.split(",");
            sslEngine.setEnabledProtocols(protocols);
            logger.debug("Applied protocols from proxy config for StartTLS: {}", Arrays.toString(protocols));
        } else {
            String[] defaultProtocols = {"TLSv1.3", "TLSv1.2"};
            sslEngine.setEnabledProtocols(defaultProtocols);
            logger.debug("No sslProtocols in proxy config, using default: {}", Arrays.toString(defaultProtocols));
        }

        SslHandler sslHandler = new SslHandler(sslEngine);
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
        logger.info("Reached channelRead0 with {} bytes", msg.readableBytes());
        if (!checkMessageSize(msg)) {
            logger.error("Message size check failed, closing connection");
            ctx.close();
            return;
        }

        TargetServerInfo targetInfo = negotiateTargetServer(ctx, msg);
        String target = targetInfo.getTarget();

        if (target != null) {
            ConfigProperties.LdapServerConfig config = configProperties.getLdapServerConfigs().get(target);
            if (config == null) {
                logger.error("No configuration found for target server: {}", target);
                ctx.close();
                return;
            }

            boolean connected = ldapService.testConnection(target);
            if (!connected) {
                logger.error("Failed to connect to target server: {}", target);
                ctx.close();
                return;
            }

            int messageType = targetInfo.getMessageType();
            int messageId = targetInfo.getMessageId();

            if (messageType == LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST) {
                return;
            } else if (messageType == LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST) {
                logger.debug("Received BindRequest with messageId: {}", messageId);
                sendBindResponse(ctx, messageId, 0);
            } else if (messageType == LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST) {
                logger.debug("Received SearchRequest with messageId: {}", messageId);
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

            if (messageType == LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST) {
                ExtendedRequestProtocolOp extendedOp = ldapMessage.getExtendedRequestProtocolOp();
                if (LdapConstants.START_TLS_OID.equals(extendedOp.getOID())) {
                    logger.info("Received StartTLS request from client");
                    handleStartTls(ctx, messageId);
                    return new TargetServerInfo(null, ldapMessage, messageType, messageId, configProperties);
                }
            } else if (messageType == LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST) {
                SearchRequestProtocolOp searchOp = ldapMessage.getSearchRequestProtocolOp();
                String dn = searchOp.getBaseDN();
                for (Map.Entry<String, ConfigProperties.LdapServerConfig> entry : configProperties.getLdapServerConfigs().entrySet()) {
                    if (dn.equals(entry.getValue().getVirtualDn())) {
                        return new TargetServerInfo(entry.getKey(), ldapMessage, messageType, messageId,configProperties);
                    }
                }
                logger.warn("No remote LDAP server found for DN: {}", dn);
                return new TargetServerInfo("dc-01", ldapMessage, messageType, messageId, configProperties);
            } else if (messageType == LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST) {
                String dn = ldapMessage.getBindRequestProtocolOp().getBindDN();
                for (Map.Entry<String, ConfigProperties.LdapServerConfig> entry : configProperties.getLdapServerConfigs().entrySet()) {
                    if (dn.equals(entry.getValue().getVirtualDn())) {
                        return new TargetServerInfo(entry.getKey(), ldapMessage, messageType, messageId, configProperties);
                    }
                }
                logger.warn("No remote LDAP server found for bind DN: {}", dn);
                return new TargetServerInfo("dc-01", ldapMessage, messageType, messageId, configProperties);
            }
            logger.debug("Unhandled message type: {}", messageType);
            return new TargetServerInfo("dc-01", ldapMessage, messageType, messageId, configProperties);
        } catch (Exception e) {
            logger.error("Failed to parse LDAP request", e);
            return new TargetServerInfo("dc-01", null, -1, -1, configProperties);
        }
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        logger.info("Client connected: {}", ctx.channel().remoteAddress());
        SslHandler sslHandler = ctx.pipeline().get(SslHandler.class);
        if (sslHandler != null) {
            logger.info("SSL Handler found in pipeline, waiting for handshake...");
            sslHandler.handshakeFuture().addListener(future -> {
                if (future.isSuccess()) {
                    logger.info("SSL handshake successful with cipher: {}", sslHandler.engine().getSession().getCipherSuite());
                } else {
                    logger.error("SSL handshake failed", future.cause());
                    ctx.close();
                }
            });
        } else {
            logger.warn("SSL Handler not found in pipeline");
        }
    }

    private void sendBindResponse(ChannelHandlerContext ctx, int messageId, int resultCode) {
        ByteBuf response = Unpooled.buffer();
        response.writeByte(0x30);
        response.writeByte(0x0C);
        response.writeByte(0x02);
        response.writeByte(0x01);
        response.writeByte(messageId);
        response.writeByte(0x61);
        response.writeByte(0x07);
        response.writeByte(0x0A);
        response.writeByte(0x01);
        response.writeByte(resultCode);
        response.writeByte(0x81);
        response.writeByte(0x00);
        response.writeByte(0x82);
        response.writeByte(0x00);
        ctx.writeAndFlush(response);
    }

    private void sendSearchResponse(ChannelHandlerContext ctx, int messageId) {
        ByteBuf response = Unpooled.buffer();
        response.writeByte(0x30);
        response.writeByte(0x0A);
        response.writeByte(0x02);
        response.writeByte(0x01);
        response.writeByte(messageId);
        response.writeByte(0x65);
        response.writeByte(0x05);
        response.writeByte(0x0A);
        response.writeByte(0x01);
        response.writeByte(0x00);
        response.writeByte(0x81);
        response.writeByte(0x00);
        ctx.writeAndFlush(response);
    }
}
