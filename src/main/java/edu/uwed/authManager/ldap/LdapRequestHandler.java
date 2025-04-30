package edu.uwed.authManager.ldap;

import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.ldap.protocol.*;
import com.unboundid.ldap.sdk.*;
import edu.uwed.authManager.configuration.ConfigProperties;
import io.netty.buffer.ByteBuf;
import io.netty.channel.*;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslHandler;
import io.netty.handler.timeout.ReadTimeoutException;
import io.netty.util.AttributeKey;
import org.apache.logging.log4j.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.ByteArrayInputStream;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.unboundid.ldap.sdk.SimpleBindRequest;

public class LdapRequestHandler extends SimpleChannelInboundHandler<ByteBuf> {

    private static final Logger logger = LoggerFactory.getLogger(LdapRequestHandler.class);

    private static final AttributeKey<Integer> LAST_MESSAGE_ID = AttributeKey.valueOf("lastMessageId");
    private static final AttributeKey<Byte> LAST_MESSAGE_TYPE = AttributeKey.valueOf("lastMessageType");
    private static final AttributeKey<Set<String>> REQUESTED_ATTRIBUTES = AttributeKey.valueOf("requestedAttributes");
    private static final AttributeKey<LdapMITM> LDAP_SEARCH_MITM = AttributeKey.valueOf("ldapSearchMITM");

    private final ConfigProperties configProperties;
    private final SslContext proxySslContext;
    private final SSLContext proxyTlsContext;
    private final SSLSocketFactory targetSecureSocketFactory;
    private final LDAPConnectionPoolFactory targetConnectionPoolFactory;
    private final LdapMITM ldapMITM; // Новый член класса
    private final ExecutorService executor;

//    private int lastMessageId = -1; // Сохраняем последний messageId
//    private int lastMessageType = -1; // Сохраняем последний messageType
//
//    private Channel proxyChannel = null;
//    private LDAPConnection targetConn = null;
//    private boolean isTargetBound = false;

    private final Map<Integer, Integer> messageIdMapping = new ConcurrentHashMap<>();

    public LdapRequestHandler(
            ConfigProperties configProperties,
            SslContext proxySslContext,
            SSLContext proxyTlsContext,
            SSLSocketFactory targetSecureSocketFactory,
            LDAPConnectionPoolFactory targetConnectionPoolFactory,
            LdapMITM ldapMITM
    ) {
        this.configProperties = configProperties;
        this.proxySslContext = proxySslContext;
        this.proxyTlsContext = proxyTlsContext;
        this.targetSecureSocketFactory = targetSecureSocketFactory;
        this.targetConnectionPoolFactory = targetConnectionPoolFactory;
        this.ldapMITM = ldapMITM;
        this.executor = Executors.newFixedThreadPool(configProperties.getTargetConfig().getThreadPoolSize());
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, ByteBuf msg) throws Exception {
        logger.debug("Received ByteBuf: readableBytes={}", msg.readableBytes());
        byte[] debugBytes = new byte[msg.readableBytes()];
        msg.getBytes(msg.readerIndex(), debugBytes);
        logger.debug("Buffer contents: {}", Arrays.toString(debugBytes));

        if (msg.readableBytes() < 2) {
            logger.error("Received empty or too small buffer: {} bytes", msg.readableBytes());
            ctx.close();
            return;
        }
        if (!checkMessageSize(msg)) {
            logger.error("Message size check failed, closing connection");
            ctx.close();
            return;
        }

        TargetServerInfo targetInfo = negotiateTargetServer(ctx, msg);
        LdapConstants.PROXY_ENDPOINT endpoint = targetInfo.getEndpoint();
        byte messageType = targetInfo.getMessageType();
        LDAPMessage ldapMessage = targetInfo.getLdapMessage();
        int clientMessageId = targetInfo.getMessageId();
        LdapConstants.BIND_STATUS bindStatus = targetInfo.getBindStatus();

        // Сохраняем контекст в атрибутах канала
        ctx.channel().attr(LAST_MESSAGE_ID).set(clientMessageId);
        ctx.channel().attr(LAST_MESSAGE_TYPE).set(messageType);

        switch (endpoint) {
            case PROXY:
                if (messageType == LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST) {
                    LdapUtils.sendBindResponse(ctx, clientMessageId,
                            bindStatus == LdapConstants.BIND_STATUS.SUCCESS
                                    ? ResultCode.SUCCESS
                                    : ResultCode.INVALID_CREDENTIALS);
                } else if (messageType == LDAPMessage.PROTOCOL_OP_TYPE_UNBIND_REQUEST) {
                    processUnbindRequest(ctx, clientMessageId, null, endpoint);
                }
                return;
            case TARGET:
                LDAPConnectionPool pool = targetConnectionPoolFactory.getConnectionPool(targetInfo);
                LDAPConnection conn = pool.getConnection();
                conn.getConnectionOptions().setResponseTimeoutMillis(
                        configProperties.getTargetConfig().getOperationTimeoutMs());

                switch (messageType) {
                    case LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST:
                        executor.submit(() -> {
                            try {
                                BindRequestProtocolOp bindOp = ldapMessage.getBindRequestProtocolOp();
                                String bindDN = bindOp.getBindDN();
                                String password = bindOp.getSimplePassword() != null ? bindOp.getSimplePassword().toString() : null;

                                String effectiveBindDN = ldapMITM.processBindExpression(bindDN, password, conn);
                                if (effectiveBindDN == null) {
                                    logger.warn("BIND rejected for bindDN '{}': domain not allowed", bindDN);
                                    LdapUtils.sendBindResponse(ctx, clientMessageId, ResultCode.INVALID_CREDENTIALS);
                                    pool.releaseConnection(conn);
                                    return;
                                }

                                SimpleBindRequest bindRequest = new SimpleBindRequest(effectiveBindDN, password);
                                long startTime = System.currentTimeMillis();
                                BindResult bindResult = conn.bind(bindRequest);
                                long duration = System.currentTimeMillis() - startTime;
                                logger.info("BIND operation for bindDN '{}' completed in {} ms with result: {}",
                                        effectiveBindDN, duration, bindResult.getResultCode());
                                LdapUtils.sendBindResponse(ctx, clientMessageId, bindResult.getResultCode());
                                pool.releaseConnection(conn);
                            } catch (LDAPException e) {
                                logger.error("BIND operation for bindDN failed: {}", e.getMessage(), e);
                                LdapUtils.sendBindResponse(ctx, clientMessageId, e.getResultCode());
                                pool.releaseDefunctConnection(conn);
                            }
                        });
                        break;

                    case LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST:
                        executor.submit(() -> {
                            try {
                                ConfigProperties.TargetConfig targetConfig = configProperties.getTargetConfig();
                                SimpleBindRequest searchBindRequest = new SimpleBindRequest(
                                        targetConfig.getUserDn(), targetConfig.getPassword());
                                conn.bind(searchBindRequest);

                                SearchRequestProtocolOp searchRequestOp = ldapMessage.getSearchRequestProtocolOp();
                                Filter originalFilter = searchRequestOp.getFilter();
                                List<String> requestedAttributes = searchRequestOp.getAttributes();

                                ctx.channel().attr(REQUESTED_ATTRIBUTES).set(new HashSet<>(requestedAttributes));

                                List<String> attributesToRequest = ldapMITM.enhanceRequestedAttributes(requestedAttributes);

                                LdapMITM.FilterResult filterResult = ldapMITM.generateLdapFilter(originalFilter);
                                Filter enhancedFilter = filterResult.getFilter();
                                String filterValue = filterResult.getFilterValue();

                                LdapProxyStreamingSearchResultListener listener = new LdapProxyStreamingSearchResultListener(
                                        ctx,
                                        ldapMITM.getFilter(),
                                        ldapMITM.getEntryProcessor(requestedAttributes, filterValue),
                                        clientMessageId,
                                        pool, conn
                                );

                                SearchRequest searchRequest = new SearchRequest(
                                    listener,
                                    searchRequestOp.getBaseDN(),
                                    searchRequestOp.getScope(),
                                    configProperties.getTargetConfig().getReferralPolicy(),
                                    (int)configProperties.getTargetConfig().getMaxRecords(),
                                    (int)configProperties.getTargetConfig().getSearchAsyncTimeoutSec(),
                                    false,
                                    enhancedFilter,
                                    attributesToRequest.toArray(new String[0])
                                );

                                AsyncRequestID requestId = conn.asyncSearch(searchRequest);
                                logger.debug("Submitted SEARCH task for clientMessageId: {}, attributes: {}",
                                        clientMessageId, attributesToRequest);
                            } catch (LDAPException e) {
                                logger.error("Search initiation failed for messageId {}: {}", clientMessageId, e.getMessage(), e);
                                LdapUtils.sendSearchDoneResponse(ctx, clientMessageId, e.getResultCode());
                                pool.releaseDefunctConnection(conn);
                            }
                        });
                        break;

                    case LDAPMessage.PROTOCOL_OP_TYPE_UNBIND_REQUEST:
                        processUnbindRequest(ctx, clientMessageId, conn, endpoint);
                        pool.releaseConnection(conn);
                        break;

                    default:
                        logger.warn("Unsupported message type: {}", messageType);
                        LdapUtils.sendBindResponse(ctx, clientMessageId, ResultCode.PROTOCOL_ERROR);
                        pool.releaseConnection(conn);
                }
                return;
            default:
                logger.warn("Unknown endpoint: {}", endpoint);
                ctx.close();
        }
    }

    private void processUnbindRequest(ChannelHandlerContext ctx, int messageId, LDAPConnection conn, LdapConstants.PROXY_ENDPOINT endpoint) {
        logger.info("Processing UNBIND request for clientMessageId: {}, endpoint: {}", messageId, endpoint);
        if (endpoint == LdapConstants.PROXY_ENDPOINT.TARGET && conn != null) {
            try {
                conn.close();
                logger.debug("Closed connection to target server for clientMessageId: {}", messageId);
            } catch (Exception e) {
                logger.error("Failed to close connection to target server for clientMessageId: {}", messageId, e);
            }
        }
        long delay = configProperties.getTargetConfig().getDisconnectDelayMs();
        if (delay > 0) {
            ctx.executor().schedule(() -> {
                logger.info("Closing connection after unbind delay for clientMessageId: {}", messageId);
                ctx.close();
            }, delay, TimeUnit.MILLISECONDS);
        } else {
            ctx.close();
        }
    }

    private boolean checkMessageSize(ByteBuf msg) {
        int maxMessageSize = configProperties.getProxyConfig().getMaxMessageSize();
        if (msg.readableBytes() > maxMessageSize) {
            logger.error("Message size exceeds maximum allowed: {} > {}", msg.readableBytes(), maxMessageSize);
            return false;
        }
        return true;
    }

    // Определить применительно к какому серверу выполнять последующие LDAP-операции :
    // TargetServerInfo.target = null => применительно к данному прокси
    // TargetServerInfo.target != null => применительно к удаленному серверу
    private TargetServerInfo negotiateTargetServer(ChannelHandlerContext ctx, ByteBuf msg) {
        int messageId = -1;
        byte messageType = -1;
        LDAPMessage ldapMessage = null;

        try {
            byte[] bytes = new byte[msg.readableBytes()];
            msg.getBytes(msg.readerIndex(), bytes);
            ASN1StreamReader asn1Reader = new ASN1StreamReader(new ByteArrayInputStream(bytes));

            ldapMessage = LDAPMessage.readFrom(asn1Reader, true);
            messageId = ldapMessage.getMessageID();
            messageType = ldapMessage.getProtocolOpType();

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
            logger.warn("Unsupported message type: {}", messageType);
            return new TargetServerInfo(
                    LdapConstants.PROXY_ENDPOINT.NONE, configProperties, ldapMessage, messageType, messageId, LdapConstants.BIND_STATUS.NONE
            );
        } catch (Exception e) {
            logger.error("Failed to parse LDAP request: {}", e.getMessage(), e);
            byte[] errorBytes = new byte[msg.readableBytes()];
            msg.getBytes(msg.readerIndex(), errorBytes);
            logger.debug("Buffer contents on error: {}", Arrays.toString(errorBytes));

            if (e instanceof LDAPException) {
                LDAPException ldapEx = (LDAPException) e;
                ResultCode resultCode = ldapEx.getResultCode();

                if (resultCode == ResultCode.SERVER_DOWN) {
                    logger.error("Target LDAP server is down, sending error response to client for messageId: {}", messageId);
                    switch (messageType) {
                        case LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST:
                            LdapUtils.sendSearchDoneResponse(ctx, messageId, ResultCode.SERVER_DOWN);
                            break;
                        case LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST:
                            LdapUtils.sendBindResponse(ctx, messageId, ResultCode.SERVER_DOWN);
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
                    switch (messageType) {
                        case LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST:
                            logger.debug("Sending SearchResultDone with PROTOCOL_ERROR for messageId: {}", messageId);
                            LdapUtils.sendSearchDoneResponse(ctx, messageId, ResultCode.PROTOCOL_ERROR);
                            break;
                        case LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST:
                            logger.debug("Sending BindResponse with PROTOCOL_ERROR for messageId: {}", messageId);
                            LdapUtils.sendBindResponse(ctx, messageId, ResultCode.PROTOCOL_ERROR);
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
        ctx.channel().attr(LAST_MESSAGE_ID).set(-1);
        ctx.channel().attr(LAST_MESSAGE_TYPE).set((byte) -1);
        ctx.channel().attr(LDAP_SEARCH_MITM).set(new LdapMITM(configProperties));
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        logger.info("Client disconnected: {}", ctx.channel().remoteAddress());
        ctx.channel().attr(LAST_MESSAGE_ID).set(-1);
        ctx.channel().attr(LAST_MESSAGE_TYPE).set((byte) -1);
        ctx.channel().attr(REQUESTED_ATTRIBUTES).set(null);
        ctx.channel().attr(LDAP_SEARCH_MITM).set(null);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        Integer lastMessageId = ctx.channel().attr(LAST_MESSAGE_ID).get();
        Byte lastMessageType = ctx.channel().attr(LAST_MESSAGE_TYPE).get();

        if (lastMessageId == null || lastMessageType == null) {
            lastMessageId = -1;
            lastMessageType = -1;
        }

        if (cause instanceof ReadTimeoutException) {
            logger.error("Read timeout occurred, sending PROTOCOL_ERROR response");
            if (lastMessageId != -1 && lastMessageType != -1) {
                switch (lastMessageType) {
                    case LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST:
                        LdapUtils.sendSearchDoneResponse(ctx, lastMessageId, ResultCode.PROTOCOL_ERROR);
                        break;
                    case LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST:
                        LdapUtils.sendBindResponse(ctx, lastMessageId, ResultCode.PROTOCOL_ERROR);
                        break;
                    default:
                        logger.warn("Cannot send error response for messageType: {}", lastMessageType);
                        break;
                }
            }
        } else {
            logger.error("Unexpected error in LdapRequestHandler: {}", cause.getMessage(), cause);
        }

        ctx.channel().attr(LAST_MESSAGE_ID).set(-1);
        ctx.channel().attr(LAST_MESSAGE_TYPE).set((byte) -1);
        ctx.close();
    }

    // защищенный канал с клиентом : отравка согласия на TLS-сессию с нашим сертификатом и поддерживаемыми нами протоколами,
    // и ожидание подтверждения от клиента после проверки наших реквизитов на его стороне
    private void handleStartTls(ChannelHandlerContext ctx, int messageId) throws Exception {
        logger.debug("Handling StartTLS request");
        LdapUtils.sendStartTlsResponse(ctx, messageId);

        logger.debug("Adding SslHandler with Java SSLContext for StartTLS");
        SSLEngine sslEngine = proxyTlsContext.createSSLEngine();
        sslEngine.setUseClientMode(false);
        sslEngine.setNeedClientAuth(false);

        String sslProtocols = configProperties.getProxyConfig() != null ? configProperties.getProxyConfig().getSslProtocols() : null;
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

}
