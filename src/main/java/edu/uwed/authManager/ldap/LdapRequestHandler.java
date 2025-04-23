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
import io.netty.handler.timeout.ReadTimeoutException;
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
    private final LdapSearchMITM ldapSearchMITM; // Новый член класса

    private int lastMessageId = -1; // Сохраняем последний messageId
    private int lastMessageType = -1; // Сохраняем последний messageType

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
            LdapSearchMITM ldapSearchMITM
    ) {
        this.configProperties = configProperties;
        this.proxySslContext = proxySslContext;
        this.proxyTlsContext = proxyTlsContext;
        this.targetSecureSocketFactory = targetSecureSocketFactory;
        this.targetConnectionPoolFactory = targetConnectionPoolFactory;
        this.ldapSearchMITM = ldapSearchMITM;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, ByteBuf msg) throws Exception {
        // Логируем содержимое буфера для отладки
        logger.debug("Received ByteBuf: readableBytes={}", msg.readableBytes());
        byte[] debugBytes = new byte[msg.readableBytes()];
        msg.getBytes(msg.readerIndex(), debugBytes);
        logger.debug("Buffer contents: {}", Arrays.toString(debugBytes));

        // Проверяем, что буфер не пустой
        if (msg.readableBytes() < 2) {
            logger.error("Received empty or too small buffer: {} bytes", msg.readableBytes());
            ctx.close();
            return;
        }
        // Проверяем максимальный размер сообщения
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
                } else
                if (messageType == LDAPMessage.PROTOCOL_OP_TYPE_UNBIND_REQUEST) {
                    processUnbindRequest(ctx, clientMessageId, null, endpoint);
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

                            BindRequestProtocolOp bindOp = ldapMessage.getBindRequestProtocolOp();
                            String bindDN = bindOp.getBindDN();
                            String password = bindOp.getSimplePassword() != null ? bindOp.getSimplePassword().toString() : null;

                            // Обрабатываем bindExpression через LdapSearchMITM
                            String effectiveBindDN = ldapSearchMITM.processBindExpression(bindDN, password, conn);
                            if (effectiveBindDN == null) {
                                logger.warn("BIND rejected for bindDN '{}': domain not allowed", bindDN);
                                sendBindResponse(ctx, clientMessageId, ResultCode.INVALID_CREDENTIALS); // Код 49
                                break;
                            }

                            SimpleBindRequest bindRequest = new SimpleBindRequest(effectiveBindDN, password);

                            serverMessageId = bindRequest.getLastMessageID();
                            messageIdMapping.put(serverMessageId, clientMessageId);

                            BindResult bindResult = conn.bind(bindRequest);
                            sendBindResponse(ctx, clientMessageId, bindResult.getResultCode());
                            break;

                        case LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST:

                            // Выполняем bind с фиксированными учетными данными перед поиском
                            ConfigProperties.TargetConfig targetConfig = configProperties.getTargetConfig();
                            conn.bind(targetConfig.getUserDn(), targetConfig.getPassword());

                            Filter originalFilter = ldapMessage.getSearchRequestProtocolOp().getFilter();
                            Filter enhancedFilter = ldapSearchMITM.generateLdapFilter(originalFilter);

                            SearchRequest searchRequest = new SearchRequest(
                                    ldapMessage.getSearchRequestProtocolOp().getBaseDN(),
                                    ldapMessage.getSearchRequestProtocolOp().getScope(),
                                    enhancedFilter,
                                    ldapMessage.getSearchRequestProtocolOp().getAttributes().toArray(new String[0])
                            );

                            serverMessageId = searchRequest.getLastMessageID();
                            messageIdMapping.put(serverMessageId, clientMessageId);

                            // Передаём clientMessageId вместо serverMessageId, чтобы использовать его напрямую
                            LdapProxyStreamingSearchResultListener listener = new LdapProxyStreamingSearchResultListener(
                                    ctx,
                                    ldapSearchMITM.getFilter(),
                                    ldapSearchMITM.getEntryProcessor(),
                                    clientMessageId // Используем clientMessageId вместо serverMessageId
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

                        case LDAPMessage.PROTOCOL_OP_TYPE_UNBIND_REQUEST:
                            processUnbindRequest(ctx, clientMessageId, conn, endpoint);
                            return;

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
                        case LDAPMessage.PROTOCOL_OP_TYPE_UNBIND_REQUEST:
                            logger.info("Closing connection after UNBIND error for clientMessageId: {}", clientMessageId);
                            ctx.close();
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

    private void processUnbindRequest(ChannelHandlerContext ctx, int messageId, LDAPConnection conn, LdapConstants.PROXY_ENDPOINT endpoint) {
        logger.info("Processing UNBIND request for clientMessageId: {}, endpoint: {}", messageId, endpoint);
        if (endpoint == LdapConstants.PROXY_ENDPOINT.TARGET && conn != null) {
            try {
                conn.close(); // Закрываем соединение с целевым сервером, отправляя UNBIND_REQUEST
                logger.debug("Closed connection to target server for clientMessageId: {}", messageId);
            } catch (Exception e) {
                logger.error("Failed to close connection to target server for clientMessageId: {}", messageId, e);
            }
        }
        ctx.close(); // Закрываем клиентское соединение
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
        int messageId = -1;
        int messageType = -1;
        LDAPMessage ldapMessage = null;

        try {
            byte[] bytes = new byte[msg.readableBytes()];
            msg.getBytes(msg.readerIndex(), bytes);
            ASN1StreamReader asn1Reader = new ASN1StreamReader(new ByteArrayInputStream(bytes));

            // Парсим сообщение и сохраняем messageId и messageType
            ldapMessage = LDAPMessage.readFrom(asn1Reader, true);
            messageId = ldapMessage.getMessageID();
            messageType = ldapMessage.getProtocolOpType();

            // Сохраняем messageId и messageType для обработки тайм-аута
            this.lastMessageId = messageId;
            this.lastMessageType = messageType;

            String targetUrl = configProperties.getTargetConfig().getUrl();

            if (messageType == LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST) {
                ExtendedRequestProtocolOp extendedOp = ldapMessage.getExtendedRequestProtocolOp();
                if (LdapConstants.START_TLS_OID.equals(extendedOp.getOID())) {
                    logger.info("Received StartTLS request from client");
                    handleStartTls(ctx, messageId);
                    return new TargetServerInfo(
                            LdapConstants.PROXY_ENDPOINT.PROXY, configProperties, ldapMessage, messageType, messageId, LdapConstants.BIND_STATUS.NONE
                    );
                }
            } else if (messageType == LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST) {
                String dn = ldapMessage.getBindRequestProtocolOp().getBindDN();
                String password = ldapMessage.getBindRequestProtocolOp().getSimplePassword().stringValue();

                List<ConfigProperties.ProxyUser> proxyUsers = configProperties.getProxyUsers();

                for (ConfigProperties.ProxyUser proxyUser : proxyUsers) {
                    if (proxyUser.getDn().equals(dn)) {
                        if (proxyUser.getPassword().equals(password)) {
                            return new TargetServerInfo(
                                    LdapConstants.PROXY_ENDPOINT.PROXY, configProperties, ldapMessage, messageType, messageId, LdapConstants.BIND_STATUS.SUCCESS
                            );
                        } else {
                            return new TargetServerInfo(
                                    LdapConstants.PROXY_ENDPOINT.PROXY, configProperties, ldapMessage, messageType, messageId, LdapConstants.BIND_STATUS.FAILURE
                            );
                        }
                    }
                }
                if (Strings.isBlank(targetUrl)) {
                    return new TargetServerInfo(
                            LdapConstants.PROXY_ENDPOINT.PROXY, configProperties, ldapMessage, messageType, messageId, LdapConstants.BIND_STATUS.FAILURE
                    );
                }
                return new TargetServerInfo(
                        LdapConstants.PROXY_ENDPOINT.TARGET, configProperties, ldapMessage, messageType, messageId, LdapConstants.BIND_STATUS.TARGET
                );
            } else if (messageType == LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST) {
                if (Strings.isBlank(targetUrl)) {
                    return new TargetServerInfo(
                            LdapConstants.PROXY_ENDPOINT.NONE, configProperties, ldapMessage, messageType, messageId, LdapConstants.BIND_STATUS.SUCCESS
                    );
                }
                return new TargetServerInfo(
                        LdapConstants.PROXY_ENDPOINT.TARGET, configProperties, ldapMessage, messageType, messageId, LdapConstants.BIND_STATUS.SUCCESS
                );
            } else if (messageType == LDAPMessage.PROTOCOL_OP_TYPE_UNBIND_REQUEST) {
                logger.info("Received UNBIND request from client, messageId: {}", messageId);
                return new TargetServerInfo(
                        LdapConstants.PROXY_ENDPOINT.PROXY, configProperties, ldapMessage, messageType, messageId, LdapConstants.BIND_STATUS.NONE
                );
            }
            // Для неизвестных типов запросов
            logger.warn("Unsupported message type: {}", messageType);
            return new TargetServerInfo(
                    LdapConstants.PROXY_ENDPOINT.NONE, configProperties, ldapMessage, messageType, messageId, LdapConstants.BIND_STATUS.NONE
            );
        } catch (Exception e) {
            logger.error("Failed to parse LDAP request: {}", e.getMessage(), e);
            // Дополнительно логируем содержимое буфера для отладки
            byte[] errorBytes = new byte[msg.readableBytes()];
            msg.getBytes(msg.readerIndex(), errorBytes);
            logger.debug("Buffer contents on error: {}", Arrays.toString(errorBytes));

            // Отправляем ответ с ошибкой в зависимости от типа операции
            if (e instanceof LDAPException) {
                LDAPException ldapEx = (LDAPException) e;
                ResultCode resultCode = ldapEx.getResultCode();

                // Обрабатываем случай, когда сервер недоступен (resultCode=81)
                if (resultCode == ResultCode.SERVER_DOWN) {
                    logger.error("Target LDAP server is down, sending error response to client for messageId: {}", messageId);
                    switch (messageType) {
                        case LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST:
                            sendSearchDoneResponse(ctx, messageId, ResultCode.SERVER_DOWN);
                            break;
                        case LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST:
                            sendBindResponse(ctx, messageId, ResultCode.SERVER_DOWN);
                            break;
                        case LDAPMessage.PROTOCOL_OP_TYPE_UNBIND_REQUEST:
                            logger.debug("Received UnbindRequest, closing connection for messageId: {}", messageId);
                            ctx.close();
                            break;
                        default:
                            logger.warn("Unhandled message type: {}, closing connection for messageId: {}", messageType, messageId);
                            ctx.close();
                            break;
                    }
                } else {
                    // Другие типы ошибок (например, PROTOCOL_ERROR или ошибка парсинга)
                    switch (messageType) {
                        case LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST:
                            logger.debug("Sending SearchResultDone with PROTOCOL_ERROR for messageId: {}", messageId);
                            sendSearchDoneResponse(ctx, messageId, ResultCode.PROTOCOL_ERROR);
                            break;
                        case LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST:
                            logger.debug("Sending BindResponse with PROTOCOL_ERROR for messageId: {}", messageId);
                            sendBindResponse(ctx, messageId, ResultCode.PROTOCOL_ERROR);
                            break;
                        case LDAPMessage.PROTOCOL_OP_TYPE_UNBIND_REQUEST:
                            logger.debug("Received UnbindRequest, closing connection for messageId: {}", messageId);
                            ctx.close();
                            break;
                        default:
                            logger.warn("Unhandled message type: {}, closing connection for messageId: {}", messageType, messageId);
                            ctx.close();
                            break;
                    }
                }
            } else {
                // Для других исключений (например, ASN1Exception или IOException) закрываем соединение
                logger.error("Unexpected error, closing connection for messageId: {}", messageId);
                ctx.close();
            }
            return new TargetServerInfo(
                    LdapConstants.PROXY_ENDPOINT.NONE, configProperties, null, LDAPMessage.PROTOCOL_OP_TYPE_ABANDON_REQUEST, -1, LdapConstants.BIND_STATUS.NONE
            );
        }
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
        logger.debug("Channel inactive, resetting lastMessageId and lastMessageType");
        lastMessageId = -1;
        lastMessageType = -1;
        // Никаких действий с пулом, так как соединения управляются пулом
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        if (cause instanceof ReadTimeoutException) {
            logger.error("Read timeout occurred, sending PROTOCOL_ERROR response and closing connection");
            if (lastMessageId != -1 && lastMessageType != -1) {
                switch (lastMessageType) {
                    case LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST:
                        sendSearchDoneResponse(ctx, lastMessageId, ResultCode.PROTOCOL_ERROR);
                        break;
                    case LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST:
                        sendBindResponse(ctx, lastMessageId, ResultCode.PROTOCOL_ERROR);
                        break;
                    default:
                        logger.warn("Cannot send error response for messageType: {}", lastMessageType);
                        break;
                }
                // Сбрасываем lastMessageId и lastMessageType после использования
                lastMessageId = -1;
                lastMessageType = -1;
            }
        } else {
            logger.error("Unexpected error in LdapRequestHandler: {}", cause.getMessage(), cause);
            // Сбрасываем lastMessageId и lastMessageType в случае любой ошибки
            lastMessageId = -1;
            lastMessageType = -1;
        }
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
