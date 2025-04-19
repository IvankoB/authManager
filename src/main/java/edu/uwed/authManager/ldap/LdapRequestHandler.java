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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import com.unboundid.ldap.sdk.SimpleBindRequest;

public class LdapRequestHandler extends SimpleChannelInboundHandler<ByteBuf> {

    private static final Logger logger = LoggerFactory.getLogger(LdapRequestHandler.class);

    private final ConfigProperties configProperties;
    private final SslContext proxySslContext;
    private final SSLContext proxyTlsContext;
    private final SSLSocketFactory targetSecureSocketFactory;
    private final LDAPConnectionPoolFactory targetConnectionPoolFactory;
    private final long maxMessageSize;

    private Channel proxyChannel = null;
//    private LDAPConnection targetConn = null;
//    private boolean isTargetBound = false;

    private final Map<Integer, Integer> messageIdMapping = new ConcurrentHashMap<>();

    public LdapRequestHandler(
            ConfigProperties configProperties,
            SslContext proxySslContext,
            SSLContext proxyTlsContext,
            SSLSocketFactory targetSecureSocketFactory,
            LDAPConnectionPoolFactory targetConnectionPoolFactory,
            long maxMessageSize
    ) {
        this.configProperties = configProperties;
        this.proxySslContext = proxySslContext;
        this.proxyTlsContext = proxyTlsContext;
        this.targetSecureSocketFactory = targetSecureSocketFactory;
        this.targetConnectionPoolFactory = targetConnectionPoolFactory;
        this.maxMessageSize = maxMessageSize;
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
        int clientMessageId = targetInfo.getMessageId();
        LdapConstants.BIND_STATUS bindStatus = targetInfo.getBindStatus();

        switch (endpoint) {
            case LdapConstants.PROXY_ENDPOINT.PROXY:
                if (messageType == LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST) {
                    sendBindResponse(ctx, clientMessageId,
                            bindStatus.equals(LdapConstants.BIND_STATUS.SUCCESS)
                                    ? ResultCode.SUCCESS
                                    : ResultCode.INVALID_CREDENTIALS
                    );
                }
                return;
            case LdapConstants.PROXY_ENDPOINT.TARGET:
                LDAPConnectionPool pool = null;
                LDAPConnection conn = null;
                Integer serverMessageId = null;
                try {
                    pool = targetConnectionPoolFactory.getConnectionPool(targetInfo);
                    conn = pool.getConnection();
                    logger.debug("Using connection for protocol: {}, host: {}, port: {}",
                            targetInfo.getProto(), targetInfo.getHost(), targetInfo.getPort());
                    switch (messageType) {
                        case LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST:
                            SimpleBindRequest bindRequest = new SimpleBindRequest(
                                    ldapMessage.getBindRequestProtocolOp().getBindDN(),
                                    ldapMessage.getBindRequestProtocolOp().getSimplePassword().stringValue()
                            );
                            serverMessageId = bindRequest.getLastMessageID();
                            messageIdMapping.put(serverMessageId, clientMessageId);

                            BindResult bindResult = conn.bind(bindRequest);
                            sendBindResponse(ctx, clientMessageId, bindResult.getResultCode());
                            break;

                        case LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST:
                            // Выполняем bind с фиксированными учетными данными перед поиском
                            ConfigProperties.TargetConfig targetConfig = configProperties.getTargetConfig();
                            conn.bind(targetConfig.getUserDn(), targetConfig.getPassword());

                            SearchRequest searchRequest = new SearchRequest(
                                    ldapMessage.getSearchRequestProtocolOp().getBaseDN(),
                                    ldapMessage.getSearchRequestProtocolOp().getScope(),
                                    ldapMessage.getSearchRequestProtocolOp().getFilter(),
                                    ldapMessage.getSearchRequestProtocolOp().getAttributes().toArray(new String[0])
                            );
                            serverMessageId = searchRequest.getLastMessageID();
                            messageIdMapping.put(serverMessageId, clientMessageId);

                            LdapProxyStreamingSearchResultListener listener = new LdapProxyStreamingSearchResultListener(
                                    ctx, LdapSearchMITM.filter, (entry, msgID) -> {
                                Integer originalMessageId = messageIdMapping.get(msgID);
                                return LdapSearchMITM.entryProcessor.apply(
                                        entry, originalMessageId != null ? originalMessageId : msgID
                                );
                            }, serverMessageId
                            );

                            SearchResult searchResult = conn.search(
                                    listener,
                                    searchRequest.getBaseDN(),
                                    searchRequest.getScope(),
                                    searchRequest.getFilter().toString(),
                                    searchRequest.getAttributes()
                            );
                            sendSearchDoneResponse(ctx, clientMessageId, searchResult.getResultCode());
                            break;
                        default:
                            logger.warn("Unsupported message type: {}", messageType);
                            throw new LDAPException(ResultCode.PROTOCOL_ERROR);
                    }
                } catch (Exception e) {
                    ResultCode resultCode;
                    String errorMessage;
                    if (e instanceof LDAPException) {
                        LDAPException ldapEx = (LDAPException) e;
                        resultCode = ldapEx.getResultCode();
                        errorMessage = "LDAP operation failed for clientMessageId: " + clientMessageId;
                    } else {
                        resultCode = ResultCode.OPERATIONS_ERROR;
                        errorMessage = "Unexpected error for clientMessageId: " + clientMessageId;
                    }
                    logger.error(errorMessage, e);

                    switch (messageType) {
                        case LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST:
                            sendBindResponse(ctx, clientMessageId, resultCode);
                            break;
                        case LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST:
                            sendSearchDoneResponse(ctx, clientMessageId, resultCode);
                            break;
                        default:
                            logger.warn("No response sent for unsupported message type: {}", messageType);
                            sendBindResponse(ctx, clientMessageId, ResultCode.PROTOCOL_ERROR);
                            break;
                    }
                } finally {
                    if (serverMessageId != null) {
                        messageIdMapping.remove(serverMessageId);
                        logger.debug("Removed serverMessageId {} from messageIdMapping", serverMessageId);
                    }
                    if (conn != null && pool != null) {
                        pool.releaseConnection(conn);
                    }
                }
                return;
            default:
                logger.warn("Unknown endpoint: {}", endpoint);
        }
    }

    private void channelRead01(ChannelHandlerContext ctx, ByteBuf msg) throws Exception {

//        logger.info("Reached channelRead0 with {} bytes", msg.readableBytes());
//        if (!checkMessageSize(msg)) {
//            logger.error("Message size check failed, closing connection");
//            ctx.close();
//            return;
//        }
//
//        TargetServerInfo targetInfo = negotiateTargetServer(ctx, msg);
//        LdapConstants.PROXY_ENDPOINT endpoint = targetInfo.getEndpoint();
//        int messageType = targetInfo.getMessageType();
//        LDAPMessage ldapMessage = targetInfo.getLdapMessage();
//        int clientMessageId = targetInfo.getMessageId();
//        LdapConstants.BIND_STATUS bindStatus = targetInfo.getBindStatus();
//
//        switch (endpoint) {
//            case LdapConstants.PROXY_ENDPOINT.PROXY:
//                if (messageType == LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST) {
//                    sendBindResponse(ctx, clientMessageId,
//                        bindStatus.equals(LdapConstants.BIND_STATUS.SUCCESS)
//                            ? ResultCode.SUCCESS
//                            : ResultCode.INVALID_CREDENTIALS
//                    );
//                }
//                return;
//            case LdapConstants.PROXY_ENDPOINT.TARGET:
//                LDAPConnectionPool pool = null;
//                LDAPConnection conn = null;
//                try {
//                    pool = targetConnectionPoolFactory.getConnectionPool();
//                    conn = pool.getConnection();
//                    switch (messageType) {
//                        case LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST :
//                            ResultCode rc = null;
//                            Integer serverMessageId = null;
//                            try {
//                                // Создаем SimpleBindRequest для BIND-запроса
//                                BindRequest bindRequest = new SimpleBindRequest(
//                                    ldapMessage.getBindRequestProtocolOp().getBindDN(),
//                                    ldapMessage.getBindRequestProtocolOp().getSimplePassword().stringValue()
//                                );
//                                serverMessageId = bindRequest.getLastMessageID(); // Получаем серверный messageId
//                                messageIdMapping.put(serverMessageId, clientMessageId); // Сохраняем соответствие
//                                BindResult bindResult = conn.bind(bindRequest);
//                                rc = bindResult.getResultCode();
//                            } catch (LDAPException e) {
//                                logger.error("BIND failed for DN: {}, clientMessageId: {}",
//                                    ldapMessage.getBindRequestProtocolOp().getBindDN(), clientMessageId, e
//                                );
//                                rc = e.getResultCode();
//                            } finally {
//                                sendBindResponse(ctx, clientMessageId, rc);
//                                if (serverMessageId != null) {
//                                    messageIdMapping.remove(serverMessageId); // Очистка messageIdMapping
//                                }
//                                if (conn != null) {
//                                    pool.releaseConnection(conn); // Возврат соединения в пул
//                                }
//                            }
//                            return;
//                        case LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST :
//                            try {
//                                conn.bind(
//                                    configProperties.getTargetConfig().getUserDn(),
//                                    configProperties.getTargetConfig().getPassword()
//                                );
//                            } catch(LDAPException e) {
//                                sendBindResponse(ctx, clientMessageId, e.getResultCode());
//                                return;
//                            }
//                            // Создаем SearchRequest
//                            SearchRequest searchRequest = new SearchRequest(
//                                ldapMessage.getSearchRequestProtocolOp().getBaseDN(),
//                                ldapMessage.getSearchRequestProtocolOp().getScope(),
//                                ldapMessage.getSearchRequestProtocolOp().getFilter(),
//                                ldapMessage.getSearchRequestProtocolOp().getAttributes().toArray(new String[0])
//                            );
//
//                            int serverMessageId = searchRequest.getLastMessageID(); // Получаем сгенерированный messageId
//                            messageIdMapping.put(serverMessageId, clientMessageId); // Сохраняем соответствие
//
//                            ///////// Создаем SearchResultListener с предикатом, messageID и функцией-обработчиком
////                            LdapProxyStreamingSearchResultListener listener = new LdapProxyStreamingSearchResultListener(
////                                ctx, LdapSearchMITM.filter, LdapSearchMITM.entryProcessor, messageID
////                            );
//
//                            LdapProxyStreamingSearchResultListener listener = new LdapProxyStreamingSearchResultListener(
//                                ctx, LdapSearchMITM.filter, (entry, msgID) -> {
//                                    // Используем clientMessageId для ответа клиенту
//                                    Integer originalMessageId = messageIdMapping.get(msgID);
//                                    return LdapSearchMITM.entryProcessor.apply(
//                                        entry,
//                                        originalMessageId != null
//                                            ? originalMessageId
//                                            : msgID);
//                                },
//                                serverMessageId
//                            );
//
//                            // Получаем messageID из SearchRequest
//                            // Если messageID не задан вручную, SDK генерирует его автоматически
//                            SearchResult searchResult;
//                            try {
//                                searchResult = conn.search(
//                                    listener,
//                                    searchRequest.getBaseDN(),
//                                    searchRequest.getScope(),
//                                    searchRequest.getFilter().toString(),
//                                    searchRequest.getAttributes()
//                                );
//                                sendSearchDoneResponse(ctx, serverMessageId, ResultCode.SUCCESS);
//                            } catch (LDAPException e) {
//                                sendSearchDoneResponse(ctx, serverMessageId, e.getResultCode());
//                            }
//                            messageIdMapping.remove(serverMessageId); // Очищаем после завершения
//                            return;
//                        default:
//                    }
//                } catch (LDAPException e) {
//                    logger.error("Failed to connect to target LDAP server", e);
//                    sendBindResponse(ctx, clientMessageId, e.getResultCode());
//                } finally {
//                    if (conn != null) {
//                        pool.releaseConnection(conn);
//                    }
//                }
//                return;
//            default:
//        }
    }

    private void sendSearchDoneResponse(ChannelHandlerContext ctx, int messageID, ResultCode resultCode) {
        ResultCode code = resultCode != null ? resultCode : ResultCode.OPERATIONS_ERROR;
        logger.debug("Sending SearchDone response for messageId: {}, resultCode: {}", messageID, code);
        try {
            SearchResultDoneProtocolOp doneOp = new SearchResultDoneProtocolOp(new LDAPResult(messageID, code));
            LDAPMessage doneMessage = new LDAPMessage(messageID, doneOp);
            byte[] doneBytes = doneMessage.encode().encode();
            ByteBuf doneBuf = ctx.alloc().buffer(doneBytes.length);
            doneBuf.writeBytes(doneBytes);
            ctx.writeAndFlush(doneBuf).addListener(future -> {
                if (!future.isSuccess()) {
                    logger.error("Failed to send search done response for messageId: {}", messageID, future.cause());
                }
            });
        } catch (Exception e) {
            logger.error("Failed to encode search done response for messageId: {}", messageID, e);
        }
    }

    private void sendSearchDoneResponse01(ChannelHandlerContext ctx, int messageID, ResultCode resultCode) {

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
        ResultCode code = resultCode != null ? resultCode : ResultCode.OPERATIONS_ERROR;
        logger.debug("Sending Bind response for messageId: {}, resultCode: {}", messageID, code);
        try {
            BindResponseProtocolOp bindOp = new BindResponseProtocolOp(new LDAPResult(messageID, code));
            LDAPMessage bindMessage = new LDAPMessage(messageID, bindOp);
            byte[] doneBytes = bindMessage.encode().encode();
            ByteBuf doneBuf = ctx.alloc().buffer(doneBytes.length);
            doneBuf.writeBytes(doneBytes);
            ctx.writeAndFlush(doneBuf).addListener(future -> {
                if (!future.isSuccess()) {
                    logger.error("Failed to send bind response for messageId: {}", messageID, future.cause());
                }
            });
        } catch (Exception e) {
            logger.error("Failed to encode bind response for messageId: {}", messageID, e);
        }
    }

    private void sendBindResponse01(ChannelHandlerContext ctx, int messageID, ResultCode resultCode) {
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
        logger.info("Client connected: {}", ctx.channel().remoteAddress());
        proxyChannel = ctx.channel();
        // Ничего не создаем, так как соединения будут браться из пула при обработке запросов
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        logger.info("Client disconnected: {}", ctx.channel().remoteAddress());
        // Очищаем ресурсы, связанные с каналом, если они есть
        if (messageIdMapping != null) {
            // Удаляем все записи messageId, связанные с этим клиентом
            messageIdMapping.entrySet().removeIf(entry -> ctx.channel().equals(proxyChannel));
        }
        // Никаких действий с пулом, так как соединения управляются пулом
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


}
