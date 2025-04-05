package edu.uwed.authManager.ldap;

import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.ldap.protocol.ExtendedRequestProtocolOp;
import com.unboundid.ldap.protocol.ExtendedResponseProtocolOp;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.SearchRequestProtocolOp;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.ByteStringBuffer;
import edu.uwed.authManager.configuration.ConfigProperties;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.ldap.core.LdapTemplate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class LdapRequestHandler extends SimpleChannelInboundHandler<ByteBuf> {

    private final ConfigProperties configProperties;
    private final SslContext clientSslContext;
    private final SSLContext startTlsSslContext;
    private final Map<String, LdapTemplate> ldapTemplates;
    private final Map<String, SslContext> proxySslContexts;
    private final Map<String, SSLContext> outgoingSslContexts;

    private Channel outboundChannel;
    private String targetServer;
    private static final Logger logger = LoggerFactory.getLogger(LdapRequestHandler.class);
    private static final String START_TLS_OID = "1.3.6.1.4.1.1466.20037";

    public LdapRequestHandler(
            ConfigProperties configProperties,
            @Qualifier("ldaps") SslContext clientSslContext,
            Map<String, LdapTemplate> ldapTemplates,
            Map<String, SslContext> proxySslContexts,
            @Qualifier("startTlsSslContext") SSLContext startTlsSslContext,
            Map<String, SSLContext> outgoingSslContexts
    ) {
        this.configProperties = configProperties;
        this.clientSslContext = clientSslContext;
        this.ldapTemplates = ldapTemplates;
        this.proxySslContexts = proxySslContexts;
        this.startTlsSslContext = startTlsSslContext;
        this.outgoingSslContexts = outgoingSslContexts;
    }

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

    private void handleStartTls(ChannelHandlerContext ctx, int messageId) throws Exception {
        logger.debug("Handling StartTLS request");

        // Сначала отправляем StartTLS-ответ
        logger.debug("Sending StartTLS response before adding SslHandler");
        sendStartTlsResponse(ctx, messageId);

        // После отправки ответа добавляем SslHandler
        logger.debug("Adding SslHandler with Java SSLContext for StartTLS");
        SSLEngine sslEngine = startTlsSslContext.createSSLEngine();
        sslEngine.setUseClientMode(false);
        sslEngine.setNeedClientAuth(false);
        sslEngine.setEnabledProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
        logger.debug("Enabled protocols: {}", Arrays.toString(sslEngine.getEnabledProtocols()));
        logger.debug("Enabled ciphers: {}", Arrays.toString(sslEngine.getEnabledCipherSuites()));

        SslHandler sslHandler = new SslHandler(sslEngine);
        sslHandler.setHandshakeTimeout(30000, TimeUnit.MILLISECONDS);
        ctx.pipeline().addFirst("ssl", sslHandler);

        // Отслеживаем handshake
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
        String target = negotiateTargetServer(ctx, msg);
        logger.debug("Negotiated target server: {}", target);

        if (target != null) {
            targetServer = target;
            if (outboundChannel == null || !outboundChannel.isActive()) {
                logger.info("Connecting to target server: {}", targetServer);
                connectToTargetServer(ctx, msg);
            } else {
                logger.debug("Forwarding message to existing outbound channel");
                outboundChannel.writeAndFlush(msg.retain());
            }
        } else {
            logger.debug("StartTLS handled, waiting for next request");
        }
    }

    private void connectToTargetServer(ChannelHandlerContext ctx, ByteBuf msg) throws Exception {
        ConfigProperties.LdapServerConfig serverConfig = configProperties.getLdapServerConfigs().get(targetServer);
        if (serverConfig == null) {
            logger.error("No server config found for target: {}", targetServer);
            ctx.close();
            return;
        }

        SslContext targetSslContext = proxySslContexts.get(targetServer); // Для LDAPS
        SSLContext targetStartTlsContext = outgoingSslContexts.get(targetServer); // Для StartTLS
        if (targetSslContext == null && targetStartTlsContext == null) {
            logger.error("No SSL context found for server: {}", targetServer);
            ctx.close();
            return;
        }

        String url = serverConfig.getUrl();
        String host = url.split("://")[1].split(":")[0];
        int port = Integer.parseInt(url.split(":")[2]);

        EventLoopGroup group = new NioEventLoopGroup();
        Bootstrap bootstrap = new Bootstrap();
        bootstrap.group(group)
                .channel(NioSocketChannel.class)
                .handler(new ChannelInitializer<NioSocketChannel>() {
                    @Override
                    protected void initChannel(NioSocketChannel ch) {
                        if (serverConfig.isStartTls() && targetStartTlsContext != null) {
                            logger.debug("Configuring StartTLS for outbound connection to {}", targetServer);
                            SSLEngine sslEngine = targetStartTlsContext.createSSLEngine(host, port);
                            sslEngine.setUseClientMode(true);
                            SslHandler sslHandler = new SslHandler(sslEngine);
                            sslHandler.setHandshakeTimeout(30000, TimeUnit.MILLISECONDS);
                            ch.pipeline().addLast(sslHandler);
                            sslHandler.handshakeFuture().addListener(future -> {
                                if (future.isSuccess()) {
                                    logger.debug("Outbound StartTLS handshake completed with {}", targetServer);
                                } else {
                                    logger.error("Outbound StartTLS handshake failed for {}", targetServer, future.cause());
                                    ch.close();
                                }
                            });
                        } else if (targetSslContext != null) {
                            logger.debug("Configuring LDAPS for outbound connection to {}", targetServer);
                            ch.pipeline().addLast(targetSslContext.newHandler(ch.alloc(), host, port));
                        }
                        ch.pipeline().addLast(new SimpleChannelInboundHandler<ByteBuf>() {
                            @Override
                            protected void channelRead0(ChannelHandlerContext ctx2, ByteBuf response) {
                                ctx.writeAndFlush(response.retain());
                            }
                        });
                    }
                });

        bootstrap.connect(host, port).addListener((ChannelFutureListener) future -> {
            if (future.isSuccess()) {
                outboundChannel = future.channel();
                logger.info("Connected to server at {}", url);
                outboundChannel.writeAndFlush(msg.retain());
            } else {
                logger.error("Failed to connect to server at {}", url, future.cause());
                ctx.close();
            }
        });
    }

    private boolean checkMessageSize(ByteBuf msg) {
        int maxMessageSize = configProperties.getProxyConfig().getMaxMessageSize();
        if (msg.readableBytes() > maxMessageSize) {
            logger.error("Message size exceeds maximum allowed: " + msg.readableBytes() + " > " + maxMessageSize);
            return false;
        }
        return true;
    }

    private String negotiateTargetServer(ChannelHandlerContext ctx, ByteBuf msg) {
        try {
            byte[] bytes = new byte[msg.readableBytes()];
            msg.getBytes(msg.readerIndex(), bytes);
            ASN1StreamReader asn1Reader = new ASN1StreamReader(new ByteArrayInputStream(bytes));
            LDAPMessage ldapMessage = LDAPMessage.readFrom(asn1Reader, true);
            int messageType = ldapMessage.getProtocolOpType();
            logger.debug("LDAP message type: {} on pipeline: {}", messageType, ctx.pipeline().names());

            if (messageType == LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST) {
                ExtendedRequestProtocolOp extendedOp = ldapMessage.getExtendedRequestProtocolOp();
                if (START_TLS_OID.equals(extendedOp.getOID())) {
                    logger.info("Received StartTLS request from client");
                    handleStartTls(ctx, ldapMessage.getMessageID());
                    return null;
                }
            } else if (messageType == LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST) {
                SearchRequestProtocolOp searchOp = ldapMessage.getSearchRequestProtocolOp();
                String dn = searchOp.getBaseDN();
                logger.debug("Search request DN: {}", dn);
                for (Map.Entry<String, ConfigProperties.LdapServerConfig> entry : configProperties.getLdapServerConfigs().entrySet()) {
                    if (dn.equals(entry.getValue().getVirtualDn())) {
                        return entry.getKey();
                    }
                }
                logger.warn("No remote LDAP server found for DN: {}", dn);
                return "dc-01";
            }
            logger.debug("Unhandled message type: {}", messageType);
            return "dc-01";
        } catch (Exception e) {
            logger.error("Failed to parse LDAP request", e);
            return "dc-01";
        }
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        logger.info("Client connected: {}", ctx.channel().remoteAddress());
        // Ничего не подключаем, ждём первого запроса
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        logger.info("Client disconnected: {}", ctx.channel().remoteAddress());
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        logger.error("Error in LDAP request handling", cause);
        ctx.close();
    }
}
