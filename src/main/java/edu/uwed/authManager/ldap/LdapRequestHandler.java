package edu.uwed.authManager.ldap;

import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.ldap.protocol.*;
import com.unboundid.ldap.sdk.*;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.util.ByteStringBuffer;
import edu.uwed.authManager.configuration.ConfigProperties;
import io.netty.buffer.ByteBuf;
import io.netty.channel.*;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslHandler;
import org.apache.logging.log4j.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.ByteArrayInputStream;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.function.BiFunction;
import java.util.function.Predicate;
import java.util.jar.Attributes;
import java.util.stream.Collectors;

public class LdapRequestHandler extends SimpleChannelInboundHandler<ByteBuf> {

    private static final Logger logger = LoggerFactory.getLogger(LdapRequestHandler.class);

    private final ConfigProperties configProperties;
    private final SslContext proxySslContext;
    private final SSLContext proxyTlsContext;
    private final SSLSocketFactory targetSecureSocketFactory;
    private final long maxMessageSize;

    private Channel proxyChannel = null;
    private LDAPConnection targetConn = null;
    private boolean isTargetBound = false;

    public LdapRequestHandler(
            ConfigProperties configProperties,
            SslContext proxySslContext,
            SSLContext proxyTlsContext,
            SSLSocketFactory targetSecureSocketFactory,
            long maxMessageSize
    ) {
        this.configProperties = configProperties;
        this.proxySslContext = proxySslContext;
        this.proxyTlsContext = proxyTlsContext;
        this.targetSecureSocketFactory = targetSecureSocketFactory;
        this.maxMessageSize = maxMessageSize;
    }

    private boolean processBind(ChannelHandlerContext ctx, String bindDn, String password, int messageID) {
        try {
            targetConn.bind( bindDn, password );
            sendBindResponse(ctx, messageID, ResultCode.SUCCESS);
            return true;
        } catch(LDAPException e) {
            sendBindResponse(ctx, messageID, e.getResultCode());
        }
        return false;
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
        LdapConstants.PROXY_ENDPOINT endpoint = targetInfo.getEndpoint();
        int messageType = targetInfo.getMessageType();
        LDAPMessage ldapMessage = targetInfo.getLdapMessage();
        int messageID = targetInfo.getMessageId();
        LdapConstants.BIND_STATUS bindStatus = targetInfo.getBindStatus();

        switch (endpoint) {
            case LdapConstants.PROXY_ENDPOINT.PROXY:
                switch (messageType) {
                    case LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST:
                        sendBindResponse(ctx, messageID,
                                bindStatus.equals(LdapConstants.BIND_STATUS.SUCCESS)
                                        ? ResultCode.SUCCESS
                                        : ResultCode.INVALID_CREDENTIALS
                        );
                        return;
                    default:
                }
                return;
            case LdapConstants.PROXY_ENDPOINT.TARGET:
                if (targetConn == null) {
                    targetConn = getLdapConnection(
                        targetInfo.getProto(),
                        targetInfo.getHost(), targetInfo.getPort(),
                        targetSecureSocketFactory
                    );
                }
                if (targetConn != null) {
                    switch (messageType) {
                        case LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST :
                            try {
                                targetConn.bind(
                                    ldapMessage.getBindRequestProtocolOp().getBindDN(),
                                    ldapMessage.getBindRequestProtocolOp().getSimplePassword().stringValue()
                                );
                                sendBindResponse(ctx, messageID, ResultCode.SUCCESS);
                            } catch(LDAPException e) {
                                sendBindResponse(ctx, messageID, e.getResultCode());
                            }
                            return;
                        case LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST :
                            try {
                                targetConn.bind(
                                    configProperties.getTargetConfig().getUserDn(),
                                    configProperties.getTargetConfig().getPassword()
                                );
                            } catch(LDAPException e) {
                                sendBindResponse(ctx, messageID, e.getResultCode());
                                return;
                            }
                            // Создаем SearchRequest
                            SearchRequest searchRequest = new SearchRequest(
                                ldapMessage.getSearchRequestProtocolOp().getBaseDN(),
                                ldapMessage.getSearchRequestProtocolOp().getScope(),
                                ldapMessage.getSearchRequestProtocolOp().getFilter(),
                                Arrays.toString(ldapMessage.getSearchRequestProtocolOp().getAttributes().toArray(String[]::new))
                            );
                            ///////// Создаем SearchResultListener с предикатом, messageID и функцией-обработчиком
                            LdapProxyStreamingSearchResultListener listener = new LdapProxyStreamingSearchResultListener(
                                ctx, LdapSearchMITM.filter, LdapSearchMITM.entryProcessor, messageID
                            );
                            // Получаем messageID из SearchRequest
                            // Если messageID не задан вручную, SDK генерирует его автоматически
                            int searchMessageID = searchRequest.getLastMessageID();
                            SearchResult searchResult;
                            try {
                                searchResult = targetConn.search(
                                    listener,
                                    searchRequest.getBaseDN(),
                                    searchRequest.getScope(),
                                    searchRequest.getFilter().toString(),
                                    searchRequest.getAttributes()
                                );
                                sendSearchDoneResponse(ctx, searchMessageID, ResultCode.SUCCESS);
                            } catch (LDAPException e) {
                                sendSearchDoneResponse(ctx, searchMessageID, e.getResultCode());
                            }
                            return;
                        default:
                    }
                }
                return;
            default:
        }
    }

    private void sendSearchDoneResponse(ChannelHandlerContext ctx, int messageID, ResultCode resultCode) {
        try {
            SearchResultDoneProtocolOp doneOp = new SearchResultDoneProtocolOp( new LDAPResult(messageID, resultCode));
            LDAPMessage doneMessage = new LDAPMessage(messageID, doneOp);
            byte[] doneBytes = doneMessage.encode().encode();
            ByteBuf doneBuf = ctx.alloc().buffer(doneBytes.length);
            doneBuf.writeBytes(doneBytes);
            ctx.writeAndFlush(doneBuf);
//            ctx.close();
        } catch (Exception e) {
//            ctx.close();
        }
    }

    private void sendBindResponse(ChannelHandlerContext ctx, int messageID, ResultCode resultCode) {
        try {
            BindResponseProtocolOp bindOp = new BindResponseProtocolOp( new LDAPResult(messageID, resultCode));
            LDAPMessage bindMessage = new LDAPMessage(messageID, bindOp);
            byte[] doneBytes = bindMessage.encode().encode();
            ByteBuf doneBuf = ctx.alloc().buffer(doneBytes.length);
            doneBuf.writeBytes(doneBytes);
            ctx.writeAndFlush(doneBuf);
//            ctx.close();
        } catch (Exception e) {
//            ctx.close();
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

    // Определить применительно к какому серверу выполнять последующие LDAP-операции :
    // TargetServerInfo.target = null => применительно к данному прокси
    // TargetServerInfo.target != null => применительно к удаленному серверу
    private TargetServerInfo negotiateTargetServer(ChannelHandlerContext ctx, ByteBuf msg) {
        try {
            byte[] bytes = new byte[msg.readableBytes()];
            msg.getBytes(msg.readerIndex(), bytes);
            ASN1StreamReader asn1Reader = new ASN1StreamReader(new ByteArrayInputStream(bytes));
            LDAPMessage ldapMessage = LDAPMessage.readFrom(asn1Reader, true);
            int messageType = ldapMessage.getProtocolOpType();
            int messageId = ldapMessage.getMessageID();

            String targetUrl = configProperties.getTargetConfig().getUrl();

            if (messageType == LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST) { // specific LDAP-startTLS request from a client

                ExtendedRequestProtocolOp extendedOp = ldapMessage.getExtendedRequestProtocolOp();
                if (LdapConstants.START_TLS_OID.equals(extendedOp.getOID())) {
                    logger.info("Received StartTLS request from client");
                    handleStartTls(ctx, messageId);
                    return new TargetServerInfo(
                        LdapConstants.PROXY_ENDPOINT.PROXY, configProperties, ldapMessage, messageType, messageId, LdapConstants.BIND_STATUS.NONE
                    );
                }

            } else
            if (messageType == LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST) { // bind authorization request to the proxy from a client

                String dn = ldapMessage.getBindRequestProtocolOp().getBindDN/* -D <xxx> в LDAPSEARCH */();
                String password = ldapMessage.getBindRequestProtocolOp().getSimplePassword().stringValue();

                List<ConfigProperties.ProxyUser> proxyUsers = configProperties.getProxyUsers();

                for (ConfigProperties.ProxyUser proxyUser : proxyUsers) {
                    // если полученный от клиента пользователь есть в списке пользователей прокси
                    if (proxyUser.getDn().equals(dn)) {
                        if (proxyUser.getPassword().equals(password)) {
                            // и его пароль совпал с ожидаемым
                            return new TargetServerInfo(
                                LdapConstants.PROXY_ENDPOINT.PROXY, configProperties, ldapMessage, messageType, messageId, LdapConstants.BIND_STATUS.SUCCESS
                            );
                        } else {
                            // если пароль не совпал - возвращаем результат с кодом ошибки
                            return new TargetServerInfo(
                                LdapConstants.PROXY_ENDPOINT.PROXY, configProperties, ldapMessage, messageType, messageId, LdapConstants.BIND_STATUS.FAILURE
                            );
                        }
                    }
                }
                // раз дошли сюда, то значит пользователь не является пользователем прокси и нужно передать его
                // на авторизацию на внешнем сервере.
                if (Strings.isBlank(targetUrl)) {
                    return new TargetServerInfo(
                        LdapConstants.PROXY_ENDPOINT.PROXY, configProperties, ldapMessage, messageType, messageId, LdapConstants.BIND_STATUS.FAILURE
                    );
                }
                return new TargetServerInfo(
                    LdapConstants.PROXY_ENDPOINT.TARGET, configProperties, ldapMessage, messageType, messageId, LdapConstants.BIND_STATUS.TARGET
                );

            } else
            if (messageType == LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST) { // search request to the proxy from a client

                if (Strings.isBlank(targetUrl)) {
                    return new TargetServerInfo(
                        null, configProperties, ldapMessage, messageType, messageId, LdapConstants.BIND_STATUS.SUCCESS
                    );
                }
                return new TargetServerInfo(
                    LdapConstants.PROXY_ENDPOINT.TARGET, configProperties, ldapMessage, messageType, messageId, LdapConstants.BIND_STATUS.SUCCESS
                );
            }
        } catch (Exception e) {
            logger.error("Failed to parse LDAP request", e);
        }
        return new TargetServerInfo(
            null, configProperties, null, LDAPMessage.PROTOCOL_OP_TYPE_ABANDON_REQUEST, -1, LdapConstants.BIND_STATUS.NONE
        );
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        //logger.info("Client connected: {}", ctx.channel().remoteAddress());
        proxyChannel = ctx.channel();
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        //logger.info("Client disconnected: {}", ctx.channel().remoteAddress());
        if (targetConn.isConnected()) {
            targetConn.close();
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        logger.error("Error in LDAP request handling", cause);
        ctx.close();
    }

    // защищенный канал с клиентом : наш ответ "TLS ОК" клиенту и ожидание подтверждения от него
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


    // защищенный канал с клиентом : отравка согласия на TLS-сессию с нашим сертификатом и поддерживаемыми нами протоколами,
    // и ожидание подтверждения от клиента после проверки наших реквизитов на его стороне
    private void handleStartTls(ChannelHandlerContext ctx, int messageId) throws Exception {
        logger.debug("Handling StartTLS request");
        sendStartTlsResponse(ctx, messageId);

        logger.debug("Adding SslHandler with Java SSLContext for StartTLS");
        SSLEngine sslEngine = proxyTlsContext.createSSLEngine();
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

    // Метод для создания LDAP-соединения
    public LDAPConnection getLdapConnection(
            LdapConstants.LDAP_PROTOCOL protocol,
            String host,
            int port,
            SSLSocketFactory socketFactory
    ) {
        LDAPConnection connection = null;
        switch (protocol) {
            case LDAP:
                try {
                    connection = new LDAPConnection(host, port);
                    return connection;
                } catch (com.unboundid.ldap.sdk.LDAPException e) {
                    throw new RuntimeException(e);
                }
            case LDAPS:
                try {
                    connection = new LDAPConnection(socketFactory, host, port);
                    return connection;
                } catch (com.unboundid.ldap.sdk.LDAPException e) {
                    throw new RuntimeException(e);
                }
            case LDAP_TLS:
                try {
                    // Создаем обычное соединение
                    connection = new LDAPConnection(host, port);
                    // Настраиваем его на использование StartTLS
                    ExtendedResult startTLSResult = connection.processExtendedOperation(
                            new StartTLSExtendedRequest(socketFactory)
                    );
                    // Проверяем успешность StartTLS с помощью getResultCode().isConnectionUsable()
                    if (!startTLSResult.getResultCode().isConnectionUsable()) {
                        logger.warn("StartTLS operation failed for server {}:{}", host, port);
                        connection.close();
                        return null;
                    }
                    return connection;
                } catch (Exception e) {
                    logger.error("It's currently unable to establish LDAP+TLS connection to server {}:{}", host, port, e);
                    if (connection != null) {
                        connection.close();
                    }
                    return null;
                }
            default:
                throw new IllegalArgumentException("Unsupported protocol: " + protocol);
        }
    }


}
