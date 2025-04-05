package edu.uwed.authManager.ldap;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.ldap.protocol.*;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.ByteString;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.ByteStringFactory;
import edu.uwed.authManager.configuration.ConfigProperties;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslHandler;
import io.netty.util.AttributeKey;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.ldap.core.LdapTemplate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import java.io.ByteArrayInputStream;
import java.security.AlgorithmConstraints;
import java.security.AlgorithmParameters;
import java.security.CryptoPrimitive;
import java.security.Key;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

@Slf4j
public class LdapRequestHandler extends SimpleChannelInboundHandler<ByteBuf> {

//    private static final Logger logger = LoggerFactory.getLogger(LdapProxyServer.class);

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

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, ByteBuf msg) throws Exception {
        msg.retain();
        ctx.channel().attr(AttributeKey.valueOf("originalMsg")).set(msg);

        try {
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
                logger.debug("Target server set to: {}", targetServer);
                if (outboundChannel == null || !outboundChannel.isActive()) {
                    logger.info("Connecting to target server: {}", targetServer);
                    connectToTargetServer(ctx, msg);
                } else {
                    logger.debug("Forwarding message to existing outbound channel");
                    outboundChannel.writeAndFlush(msg.retain());
                }
            } else {
                logger.debug("No target server negotiated, waiting for next request");
            }

        } finally {
            msg.release();
        }
    }

    private void connectToTargetServer(ChannelHandlerContext ctx, ByteBuf msg) throws Exception {
        ConfigProperties.LdapServerConfig serverConfig = configProperties.getLdapServerConfigs().get(targetServer);
        if (serverConfig == null) {
            logger.error("No server config found for target: {}", targetServer);
            ctx.close();
            return;
        }

        SslContext targetSslContext = proxySslContexts.get(targetServer);
        SSLContext targetStartTlsContext = outgoingSslContexts.get(targetServer);
        if (targetSslContext == null && targetStartTlsContext == null) {

            logger.error("No SSL context found for server: {}", targetServer);
            ctx.close();
            return;
        }

        logger.debug("Attempting to connect to target server: {}", targetServer);
        String url = serverConfig.getUrl();
        String host = url.split("://")[1].split(":")[0];
        int port = Integer.parseInt(url.split(":")[2]);
        logger.debug("Parsed host: {}, port: {}", host, port);

        EventLoopGroup group = new NioEventLoopGroup();
        Bootstrap bootstrap = new Bootstrap();

        bootstrap.group(group)
                .channel(NioSocketChannel.class)
                .handler(new ChannelInitializer<NioSocketChannel>() {
                    @Override
                    protected void initChannel(NioSocketChannel ch) {
                        if (serverConfig.isStartTls() && targetStartTlsContext != null) {
                            ch.pipeline().addLast(new StartTlsInitiator(ctx, targetServer, logger));
                            ch.pipeline().addLast(new StartTlsResponseHandler(
                                    ctx, targetStartTlsContext, host, port, targetServer, outboundChannel, logger));
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
                if (!serverConfig.isStartTls()) {
                    outboundChannel.writeAndFlush(msg.retain());
                }
            } else {
                logger.error("Failed to connect to server at {}", url, future.cause());
                ctx.close();
            }
        });
    }

    private class StartTlsInitiator extends ChannelInboundHandlerAdapter {
        private final ChannelHandlerContext clientCtx;
        private final String targetServer;
        private final Logger logger; // Добавляем поле для логгера

        public StartTlsInitiator(ChannelHandlerContext clientCtx, String targetServer, Logger logger) {
            this.clientCtx = clientCtx;
            this.targetServer = targetServer;
            this.logger = logger;
        }

        @Override
        public void channelActive(ChannelHandlerContext ctx) throws Exception {
            logger.debug("Sending StartTLS request to {}", targetServer);
            ExtendedRequest startTlsRequest = new ExtendedRequest(START_TLS_OID);
            ExtendedRequestProtocolOp requestOp = new ExtendedRequestProtocolOp(startTlsRequest);
            LDAPMessage requestMessage = new LDAPMessage(1, requestOp);

            ByteStringBuffer buffer = new ByteStringBuffer();
            requestMessage.encode().encodeTo(buffer);
            byte[] requestBytes = buffer.toByteArray();

            ByteBuf requestBuf = ctx.alloc().buffer();
            requestBuf.writeBytes(requestBytes);
            ctx.writeAndFlush(requestBuf).addListener(future -> {
                if (future.isSuccess()) {
                    logger.debug("StartTLS request sent to {}", targetServer);
                } else {
                    logger.error("Failed to send StartTLS request to {}", targetServer, future.cause());
                    ctx.close();
                }
            });

            ctx.fireChannelActive();
        }
    }

    private class StartTlsResponseHandler extends SimpleChannelInboundHandler<ByteBuf> {
        private final ChannelHandlerContext clientCtx;
        private final SSLContext targetStartTlsContext;
        private final String host;
        private final int port;
        private final String targetServer;
        private final Channel outboundChannel;
        private final Logger logger; // Добавляем поле для логгера

        public StartTlsResponseHandler(
                ChannelHandlerContext clientCtx,
                SSLContext targetStartTlsContext,
                String host,
                int port,
                String targetServer,
                Channel outboundChannel,
                Logger logger
        ) {
            this.clientCtx = clientCtx;
            this.targetStartTlsContext = targetStartTlsContext;
            this.host = host;
            this.port = port;
            this.targetServer = targetServer;
            this.outboundChannel = outboundChannel;
            this.logger = logger;
        }

        @Override
        protected void channelRead0(ChannelHandlerContext ctx, ByteBuf msg) throws Exception {
            byte[] bytes = new byte[msg.readableBytes()];
            msg.getBytes(msg.readerIndex(), bytes);
            ASN1StreamReader asn1Reader = new ASN1StreamReader(new ByteArrayInputStream(bytes));
            LDAPMessage ldapMessage = LDAPMessage.readFrom(asn1Reader, true);

            if (ldapMessage.getProtocolOpType() == LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_RESPONSE) {
                ExtendedResponseProtocolOp responseOp = ldapMessage.getExtendedResponseProtocolOp();
                if (ResultCode.valueOf(responseOp.getResultCode()) == ResultCode.SUCCESS) {
                    logger.debug("Received StartTLS response from {}: success", targetServer);

                    SSLEngine sslEngine = targetStartTlsContext.createSSLEngine(host, port);
                    sslEngine.setUseClientMode(true);

                    sslEngine.setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.3"});
                    sslEngine.setEnableSessionCreation(true);
                    // Разрешаем SHA-1 для этого соединения через SSLParameters
                    SSLParameters params = sslEngine.getSSLParameters();
                    params.setAlgorithmConstraints(new AlgorithmConstraints() {
                        @Override
                        public boolean permits(Set<CryptoPrimitive> primitives, String algorithm, AlgorithmParameters parameters) {
                            return true;
                        }

                        @Override
                        public boolean permits(Set<CryptoPrimitive> primitives, Key key) {
                            return true;
                        }

                        @Override
                        public boolean permits(Set<CryptoPrimitive> primitives, String algorithm, Key key, AlgorithmParameters parameters) {
                            return true;
                        }
                    });

                    params.setEndpointIdentificationAlgorithm(null);
                    sslEngine.setSSLParameters(params);
                    SslHandler sslHandler = new SslHandler(sslEngine);
                    sslHandler.setHandshakeTimeout(30000, TimeUnit.MILLISECONDS);
                    ctx.pipeline().addFirst("ssl", sslHandler);

                    sslHandler.handshakeFuture().addListener(future -> {
                        if (future.isSuccess()) {

                            logger.debug("Outbound StartTLS handshake completed with {}", targetServer);
                            Object originalMsgObj = clientCtx.channel().attr(AttributeKey.valueOf("originalMsg")).get();
                            if (originalMsgObj instanceof ByteBuf) {
                                ByteBuf originalMsg = (ByteBuf) originalMsgObj;
                                logger.debug("Sending original message to {} after StartTLS", targetServer);
                                if (outboundChannel != null && outboundChannel.isActive()) {
                                    outboundChannel.writeAndFlush(originalMsg.retain());
                                    logger.debug("Original message sent to {}", targetServer);
                                } else {
                                    logger.error("Outbound channel is not active for {}", targetServer);
                                    ctx.close();
                                }
                            } else {
                                logger.error("Original message is not a ByteBuf for {}", targetServer);
                                ctx.close();
                            }
                        } else {
                            logger.error("Outbound StartTLS handshake failed for {}", targetServer, future.cause());
                            ctx.close();
                        }
                    });
                } else {
                    logger.error("StartTLS failed on {}: {}", targetServer, responseOp.getResultCode());
                    ctx.close();
                }
            }
            ctx.pipeline().remove(this);
        }
    }

    private void handleStartTls(ChannelHandlerContext ctx, int messageId) throws Exception {
        logger.debug("Handling StartTLS request");

        logger.debug("Sending StartTLS response before adding SslHandler");
        sendStartTlsResponse(ctx, messageId);
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

    private void sendStartTlsResponse(ChannelHandlerContext ctx, int messageId) {
        logger.debug("Sending StartTLS response");
        ExtendedResponseProtocolOp responseOp = new ExtendedResponseProtocolOp(new LDAPResult(messageId, ResultCode.SUCCESS));
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

    private String negotiateTargetServer(ChannelHandlerContext ctx, ByteBuf msg) throws Exception {
        byte[] bytes = new byte[msg.readableBytes()];
        msg.getBytes(msg.readerIndex(), bytes);
        ASN1StreamReader asn1Reader = new ASN1StreamReader(new ByteArrayInputStream(bytes));
        LDAPMessage ldapMessage = LDAPMessage.readFrom(asn1Reader, true);
        int messageType = ldapMessage.getProtocolOpType();
        logger.debug("LDAP message type: {} on pipeline: {}", messageType, ctx.pipeline().names());

        if (messageType == LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST) {
            ExtendedRequestProtocolOp extendedRequest = ldapMessage.getExtendedRequestProtocolOp();
            if (START_TLS_OID.equals(extendedRequest.getOID())) {
                logger.info("Received StartTLS request from client");
                handleStartTls(ctx, ldapMessage.getMessageID());
                return null;
            }
        } else if (messageType == LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST) {
            SearchRequestProtocolOp searchRequest = ldapMessage.getSearchRequestProtocolOp();
            String baseDN = searchRequest.getBaseDN();
            for (Map.Entry<String, ConfigProperties.LdapServerConfig> entry : configProperties.getLdapServerConfigs().entrySet()) {
                if (baseDN.endsWith(entry.getValue().getBase())) {
                    return entry.getKey();
                }
            }
        } else if (messageType == LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST) {
            SearchRequestProtocolOp searchRequest = ldapMessage.getSearchRequestProtocolOp();
            String baseDN = searchRequest.getBaseDN();
            for (Map.Entry<String, ConfigProperties.LdapServerConfig> entry : configProperties.getLdapServerConfigs().entrySet()) {
                if (baseDN.endsWith(entry.getValue().getBase())) {
                    return entry.getKey();
                }
            }
        } else if (messageType == LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST) {
            logger.debug("Received BindRequest after StartTLS");
            BindRequestProtocolOp bindRequest = ldapMessage.getBindRequestProtocolOp();
            // Для простоты можем временно возвращать "dc-01", если у нас только один сервер
            // В будущем можно извлечь baseDN из контекста или конфигурации
            return "dc-01";
        } else {
            logger.debug("Unhandled message type: {}", messageType);
        }
        return null;
    }

    private boolean checkMessageSize(ByteBuf msg) {
        ConfigProperties.ProxyConfig proxyConfig = configProperties.getProxyConfig();
        long maxMessageSize = proxyConfig.getMaxMessageSize();
        if (msg.readableBytes() > maxMessageSize) {
            logger.error("Message size {} exceeds max allowed size {}", msg.readableBytes(), maxMessageSize);
            return false;
        }
        return true;
    }

    @Override
    public void channelReadComplete(ChannelHandlerContext ctx) throws Exception {
        ctx.flush();
        super.channelReadComplete(ctx);
    }
}
