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
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.socket.SocketChannel;
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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public class LdapRequestHandler extends SimpleChannelInboundHandler<ByteBuf> {

    private final ConfigProperties configProperties;
    private final SslContext clientSslContext;
    private final SSLContext startTlsSslContext;
    private final Map<String, LdapTemplate> ldapTemplates;
    private final Map<String, SslContext> proxySslContexts;
    private final Map<String, SSLContext> outgoingSslContexts;
    private final Map<String, Channel> outboundChannels = new ConcurrentHashMap<>();

    private final ConcurrentHashMap<String, Channel> channelMap = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Object> locks = new ConcurrentHashMap<>();

//    private Channel outboundChannel;
//    private String targetServer;
    private static final Logger logger = LoggerFactory.getLogger(LdapRequestHandler.class);
    private static final String START_TLS_OID = "1.3.6.1.4.1.1466.20037";

    // Константы для типов сообщений LDAP

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
        sendStartTlsResponse(ctx, messageId);

        logger.debug("Adding SslHandler with Java SSLContext for StartTLS");
        SSLEngine sslEngine = startTlsSslContext.createSSLEngine();
        sslEngine.setUseClientMode(false);
        sslEngine.setNeedClientAuth(false);

        // Проверяем настройки sslProtocols в ProxyConfig
        String sslProtocols = configProperties.getProxyConfig() != null ? configProperties.getProxyConfig().getSslProtocols() : null;
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
        if (!checkMessageSize(msg)) {
            logger.error("Message size check failed, closing connection");
            ctx.close();
            return;
        }

        logger.debug("Received message with {} bytes on pipeline: {}", msg.readableBytes(), ctx.pipeline().names());
        String target = negotiateTargetServer(ctx, msg);
        logger.debug("Negotiated target server: {}", target);

        if (target != null) {
            Channel outbound = outboundChannels.computeIfAbsent(target, t -> {
                try {
                    return
                    connectToTargetServer(t, configProperties.getLdapServerConfigs().get(target), ctx);
                } catch (Exception e) {
                    logger.error("Failed to connect to target: {}", t, e);
                    return null;
                }
            });
            if (outbound != null && outbound.isActive()) {
                logger.debug("Forwarding message to outbound channel for {}", target);
                outbound.writeAndFlush(msg.retain());
            } else {
                logger.error("No active outbound channel for {}", target);
                ctx.close();
            }
        } else {
            logger.debug("StartTLS handled, waiting for next request");
        }
    }

    private Channel connectToTargetServer(String targetServer, ConfigProperties.LdapServerConfig config, ChannelHandlerContext ctx) {
        // Проверяем, есть ли уже канал
        Channel channel = channelMap.get(targetServer);
        if (channel != null && channel.isActive()) {
            return channel; // Канал уже существует и активен
        }

        ConfigProperties.HostPortTuple hostPortTuple = ConfigProperties.HostPortTuple.extractHostAndPort(config.getUrl());

        // Создаём блокировку для данного targetServer
        Object lock = locks.computeIfAbsent(targetServer, k -> new Object());
        synchronized (lock) {
            // Проверяем ещё раз после синхронизации
            channel = channelMap.get(targetServer);
            if (channel != null && channel.isActive()) {
                return channel;
            }

            // Создаём новый канал
            Bootstrap bootstrap = new Bootstrap();
            bootstrap.group(ctx.channel().eventLoop())
                    .channel(NioSocketChannel.class)
                    .handler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel ch) {
                            configureOutboundSsl(ch, config, hostPortTuple.getHost(), hostPortTuple.getPort(), targetServer);
                        }
                    });

            ChannelFuture future = bootstrap.connect(hostPortTuple.getHost(), hostPortTuple.getPort());
            channel = future.channel();
            channelMap.put(targetServer, channel); // Сохраняем канал

            future.addListener((ChannelFutureListener) f -> {
                if (f.isSuccess()) {
                    logger.info("Connected to server at {}", config.getUrl());
                } else {
                    logger.error("Failed to connect to server: {}", config.getUrl(), f.cause());
                    channelMap.remove(targetServer); // Удаляем канал при ошибке
                    ctx.close();
                }
            });
        }
        return channel;
    }

    private void _configureOutboundSsl(SocketChannel ch, ConfigProperties.LdapServerConfig config, String host, int port, String targetServer) {
        boolean isLdaps = config.getUrl().toLowerCase().startsWith("ldaps://");
        SslContext targetSslContext = proxySslContexts.get(targetServer);
        if (targetSslContext == null && isLdaps) {
            targetSslContext = proxySslContexts.get("ldaps");
            logger.debug("Falling back to default 'ldaps' SslContext for {}", targetServer);
        }
        SSLContext targetStartTlsContext = outgoingSslContexts.get(targetServer);

        logger.debug("Configuring SSL for {}. isLdaps: {}, hasStartTls: {}, targetSslContext: {}, targetStartTlsContext: {}",
                targetServer, isLdaps, config.isStartTls(), targetSslContext != null, targetStartTlsContext != null);

        if (config.isStartTls() && !isLdaps/* && targetStartTlsContext != null*/) {
            logger.debug("Configuring StartTLS for outbound connection to {}", targetServer);
            SSLEngine sslEngine = targetStartTlsContext.createSSLEngine(host, port);
            sslEngine.setUseClientMode(true);

            // Создаём StartTLS-запрос с messageId = 1
            ByteBuf startTlsRequest = createStartTlsRequest(1);

            if (config.getSslProtocols() != null && !config.getSslProtocols().isEmpty()) {
                String[] protocols = Arrays.stream(config.getSslProtocols().split(","))
                        .map(String::trim)
                        .filter(s -> !s.isEmpty())
                        .toArray(String[]::new);
                sslEngine.setEnabledProtocols(protocols);
                logger.debug("Set protocols for {}: {}", targetServer, Arrays.toString(protocols));
            }

            if (config.getSslCiphers() != null && !config.getSslCiphers().isEmpty()) {
                String[] ciphers = Arrays.stream(config.getSslCiphers().split(","))
                        .map(String::trim)
                        .filter(s -> !s.isEmpty())
                        .toArray(String[]::new);
                sslEngine.setEnabledCipherSuites(ciphers);
                logger.debug("Set ciphers for {}: {}", targetServer, Arrays.toString(ciphers));
            }

            logger.debug("Enabled protocols: {}, ciphers: {}",
                    Arrays.toString(sslEngine.getEnabledProtocols()), Arrays.toString(sslEngine.getEnabledCipherSuites()));

            SslHandler sslHandler = new SslHandler(sslEngine);

            sslHandler.setHandshakeTimeout(30_000, TimeUnit.MILLISECONDS);
            ch.pipeline().addLast(sslHandler);
            sslHandler.handshakeFuture().addListener(future -> {
                if (future.isSuccess()) {
                    logger.debug("Outbound StartTLS handshake completed with {}", targetServer);
                } else {
                    logger.error("Outbound StartTLS handshake failed for {}", targetServer, future.cause());
                    ch.close();
                }
            });
        } else if (isLdaps && targetSslContext != null) {
            logger.debug("Configuring LDAPS for outbound connection to {}", targetServer);
            ch.pipeline().addLast(targetSslContext.newHandler(ch.alloc(), host, port));
        } else {
            logger.warn("No suitable SSL configuration for server: {}. isLdaps: {}, hasStartTls: {}",
                    targetServer, isLdaps, config.isStartTls());
        }
    }

    private void configureOutboundSsl(SocketChannel ch, ConfigProperties.LdapServerConfig config, String host, int port, String targetServer) {
        boolean isLdaps = config.getUrl().toLowerCase().startsWith("ldaps://");
        SslContext targetSslContext = proxySslContexts.get(targetServer);
        if (targetSslContext == null && isLdaps) {
            targetSslContext = proxySslContexts.get("ldaps");
            logger.debug("Falling back to default 'ldaps' SslContext for {}", targetServer);
        }
        SSLContext targetStartTlsContext = outgoingSslContexts.get(targetServer);

        logger.debug("Configuring SSL for {}. isLdaps: {}, hasStartTls: {}, targetSslContext: {}, targetStartTlsContext: {}",
                targetServer, isLdaps, config.isStartTls(), targetSslContext != null, targetStartTlsContext != null);

        if (config.isStartTls() && !isLdaps /* && targetStartTlsContext != null */) {
            logger.debug("Configuring StartTLS for outbound connection to {}", targetServer);

            ByteBuf startTlsRequest = createStartTlsRequest(LdapConstants.START_TLS_MESSAGE_ID);

            ch.writeAndFlush(startTlsRequest).addListener(future -> {
                if (future.isSuccess()) {
                    logger.debug("StartTLS request sent successfully to {}", targetServer);
                    ch.pipeline().addLast("startTlsHandler", new SimpleChannelInboundHandler<LdapMessageDecoder.CustomLDAPMessage>() {
                        @Override
                        protected void channelRead0(ChannelHandlerContext ctx, LdapMessageDecoder.CustomLDAPMessage msg) throws Exception {
                            if (msg.getType() == LdapConstants.EXTENDED_RESPONSE_TYPE) {
                                logger.debug("Received StartTLS response: {}", msg);

                                int resultCode = parseResultCode(msg);
                                if (resultCode == 0) {
                                    logger.info("StartTLS request accepted by {}", targetServer);

                                    SSLEngine sslEngine = targetStartTlsContext.createSSLEngine(host, port);
                                    sslEngine.setUseClientMode(true);

                                    if (config.getSslProtocols() != null && !config.getSslProtocols().isEmpty()) {
                                        String[] protocols = Arrays.stream(config.getSslProtocols().split(","))
                                                .map(String::trim)
                                                .filter(s -> !s.isEmpty())
                                                .toArray(String[]::new);
                                        sslEngine.setEnabledProtocols(protocols);
                                        logger.debug("Set protocols for {}: {}", targetServer, Arrays.toString(protocols));
                                    }

                                    if (config.getSslCiphers() != null && !config.getSslCiphers().isEmpty()) {
                                        String[] ciphers = Arrays.stream(config.getSslCiphers().split(","))
                                                .map(String::trim)
                                                .filter(s -> !s.isEmpty())
                                                .toArray(String[]::new);
                                        sslEngine.setEnabledCipherSuites(ciphers);
                                        logger.debug("Set ciphers for {}: {}", targetServer, Arrays.toString(ciphers));
                                    }

                                    logger.debug("Enabled protocols: {}, ciphers: {}",
                                            Arrays.toString(sslEngine.getEnabledProtocols()),
                                            Arrays.toString(sslEngine.getEnabledCipherSuites()));

                                    SslHandler sslHandler = new SslHandler(sslEngine);
                                    sslHandler.setHandshakeTimeout(30_000, TimeUnit.MILLISECONDS);
                                    ctx.pipeline().addLast(sslHandler);
                                    sslHandler.handshakeFuture().addListener(future1 -> {
                                        if (future1.isSuccess()) {
                                            logger.debug("Outbound StartTLS handshake completed with {}", targetServer);
                                        } else {
                                            logger.error("Outbound StartTLS handshake failed for {}", targetServer, future1.cause());
                                            ctx.close();
                                        }
                                    });

                                    ctx.pipeline().remove(this);
                                } else {
                                    logger.error("StartTLS request failed with resultCode: {} for server {}", resultCode, targetServer);
                                    ctx.close();
                                }
                            } else {
                                logger.error("Unexpected response type: {} from server {}", msg.getType(), targetServer);
                                ctx.close();
                            }
                        }

                        @Override
                        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
                            logger.error("Error while waiting for StartTLS response from {}: {}", targetServer, cause.getMessage(), cause);
                            ctx.close();
                        }
                    });
                } else {
                    logger.error("Failed to send StartTLS request to {}: {}", targetServer, future.cause());
                    ch.close();
                }
            });
        } else if (isLdaps && targetSslContext != null) {
            logger.debug("Configuring LDAPS for outbound connection to {}", targetServer);
            ch.pipeline().addLast(targetSslContext.newHandler(ch.alloc(), host, port));
        } else {
            logger.warn("No suitable SSL configuration for server: {}. isLdaps: {}, hasStartTls: {}",
                    targetServer, isLdaps, config.isStartTls());
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

    /**
     * Создаёт StartTLS Extended Request в формате LDAP.
     * @param messageId Идентификатор сообщения.
     * @return ByteBuf с закодированным StartTLS-запросом.
     */
    private ByteBuf createStartTlsRequest(int messageId) {
        // ASN.1 структура:
        // 0x30 - SEQUENCE (универсальный тег для LDAPMessage)
        // 0x80 - messageID (контекстный тег 0)
        // 0x77 - ExtendedRequest (контекстный тег 23, в вашем декодере 96)
        // 0x80 - extendedRequest OID (контекстный тег 0)
        ByteBuf request = Unpooled.buffer();
        request.writeByte(0x30); // SEQUENCE
        request.writeByte(0x0F); // Длина всей структуры (15 байт)
        request.writeByte(0x02); // INTEGER (messageID)
        request.writeByte(0x01); // Длина messageID
        request.writeByte(messageId); // messageID
        request.writeByte(0x77); // ExtendedRequest (код 23, в вашем декодере 96)
        request.writeByte(0x0A); // Длина ExtendedRequest
        request.writeByte(0x80); // OID (контекстный тег 0)
        request.writeByte(0x08); // Длина OID
        // OID 1.3.6.1.4.1.1466.20037 в DER-кодировании
        request.writeBytes(new byte[] {
                (byte) 0x2B, (byte) 0x06, (byte) 0x01, (byte) 0x04,
                (byte) 0x01, (byte) 0x92, (byte) 0x26, (byte) 0x05
        });
        return request;
    }

    private int parseResultCode(LdapMessageDecoder.CustomLDAPMessage msg) {
        int resultCode = msg.getResultCode();
        if (resultCode == -1) {
            logger.error("ResultCode not parsed for ExtendedResponse");
        }
        return resultCode;
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
            } else if (messageType == LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST) {
                String dn = ldapMessage.getBindRequestProtocolOp().getBindDN();
                logger.debug("Bind request DN: {}", dn);
                for (Map.Entry<String, ConfigProperties.LdapServerConfig> entry : configProperties.getLdapServerConfigs().entrySet()) {
                    if (dn.equals(entry.getValue().getVirtualDn())) {
                        return entry.getKey();
                    }
                }
                logger.warn("No remote LDAP server found for bind DN: {}", dn);
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
        outboundChannels.values().forEach(channel -> {
            if (channel.isActive()) {
                channel.close();
            }
        });
        outboundChannels.clear();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        logger.error("Error in LDAP request handling", cause);
        ctx.close();
    }
}
