package edu.uwed.authManager.ldap;

import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.asn1.ASN1Writer;
import com.unboundid.ldap.protocol.*;
import com.unboundid.ldap.sdk.*;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.ssl.SSLUtil;
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
import org.springframework.ldap.core.LdapTemplate;

import javax.net.ssl.*;
import java.io.ByteArrayInputStream;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.function.BiFunction;
import java.util.function.Predicate;
import java.util.stream.Collectors;

public class LdapRequestHandler extends SimpleChannelInboundHandler<ByteBuf> {

    private final ConfigProperties configProperties;
    private final SslContext inboundLdapSslContext;
    private final SSLContext inboundLdapTlsContext;
    private final Map<String, LdapTemplate> outboundLdapTemplates;
    private final Map<String, SslContext> outboundLdapSslContexts;
    private final Map<String, SSLContext> outboundLdapTlsContexts;
    private final Map<String, Channel> outboundChannels = new ConcurrentHashMap<>();
    private final Map<String, SSLSocketFactory> outboundSslSocketFactories;

    private final ConcurrentHashMap<String, Channel> channelMap = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, LDAPConnection> connMap = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Object> locks = new ConcurrentHashMap<>();

//    private Channel outboundChannel;
//    private String targetServer;
    private static final Logger logger = LoggerFactory.getLogger(LdapRequestHandler.class);

    public LdapRequestHandler(
            ConfigProperties configProperties,
            SslContext inboundLdapSslContext,
            SSLContext inboundLdapTlsContext,
            Map<String, SslContext> outboundLdapSslContexts,
            Map<String, SSLContext> outboundLdapTlsContexts,
            Map<String, LdapTemplate> outboundLdapTemplates,
            Map<String, SSLSocketFactory> outboundSslSocketFactories
    ) {
        this.configProperties = configProperties;
        this.inboundLdapSslContext = inboundLdapSslContext;
        this.outboundLdapTemplates = outboundLdapTemplates;
        this.outboundLdapSslContexts = outboundLdapSslContexts;
        this.inboundLdapTlsContext = inboundLdapTlsContext;
        this.outboundLdapTlsContexts = outboundLdapTlsContexts;
        this.outboundSslSocketFactories = outboundSslSocketFactories;
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
        SSLEngine sslEngine = inboundLdapTlsContext.createSSLEngine();
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

//        logger.debug("Received message with {} bytes on pipeline: {}", msg.readableBytes(), ctx.pipeline().names());
//        String target = negotiateTargetServer(ctx, msg);

        logger.debug("Negotiated target server: {}", target);
        if (target != null) {

            LDAPConnection conn = getLdapConnection(
                targetInfo.getProto(),
                targetInfo.getHost(), targetInfo.getPort(),
                outboundSslSocketFactories.get(target)
            );

//            if (conn == null) {
//                logger.error("Failed to establish LDAP connection for target: {}", target);
//                sendErrorResponse(ctx, 0, ResultCode.CONNECT_ERROR);
//                return;
//            }

            if (conn != null) {
                ConfigProperties.LdapServerConfig serverConfig = configProperties.getLdapServerConfigs().get(target);
                try (conn) {
                    conn.bind(
                        serverConfig.getUserDn(),
                        serverConfig.getPassword()
                    );

                    // Создаем SearchRequest
                    SearchRequest searchRequest = new SearchRequest(
                        serverConfig.getBase(),
                        SearchScope.SUB,
                        "(&(sAMAccountName=ivano))",
                        "sAMAccountName", "cn", "mail"/*,"uwedMail", "acMail"*/
                    );

                    // Получаем messageID из SearchRequest
                    // Если messageID не задан вручную, SDK генерирует его автоматически
                    int messageID = searchRequest.getLastMessageID();

                    //////////// Создаем предикат для фильтрации
                    Predicate<SearchResultEntry> filter = entry -> {
                        String mail = entry.getAttributeValue("mail");
                        String cn = entry.getAttributeValue("cn");
                        return true;
//                        return (mail != null && mail.contains("@example.com")) &&
//                                (cn != null && cn.startsWith("Ivan"));
                    };
                    ///////////////// Создаем функцию-обработчик для модификации записи
                    BiFunction<SearchResultEntry, Integer, LDAPMessage> entryProcessor = (entry, msgID) -> {
                        // Извлекаем текущие атрибуты записи в Map
                        Map<String, Attribute> updatedAttributes = entry.getAttributes().stream()
                            .collect(Collectors.toMap(
                                Attribute::getName,
                                attr -> attr,
                                (attr1, attr2) -> attr1, // В случае дубликатов берем первый атрибут
                                HashMap::new
                            ));

//                        // Пример модификации атрибутов:
//                        // 1. Удаляем атрибут cn
//                        updatedAttributes.removeIf(attr -> attr.getName().equals("cn"));
//
//                        // 2. Изменяем атрибут mail
//                        updatedAttributes.removeIf(attr -> attr.getName().equals("mail"));
//                        updatedAttributes.add(new Attribute("mail", "newemail@example.com"));
//
//                        // 3. Добавляем новый атрибут telephoneNumber
//                        updatedAttributes.add(new Attribute("telephoneNumber", "+1234567890"));

                        updatedAttributes.put(
                            "uwedMail",
                            new Attribute("uwedMail", updatedAttributes.get("sAMAccountName").getValue() + "@uwed.uz")
                        );
                        updatedAttributes.put(
                            "acMail",
                            new Attribute("acMail", updatedAttributes.get("sAMAccountName").getValue() + "@uwed.ac.uz")
                        );

                        // Преобразуем Map обратно в List для создания Entry
                        List<Attribute> updatedAttributesList = new ArrayList<>(updatedAttributes.values());
                        // Создаем новый Entry с обновленными атрибутами
                        Entry updatedEntry = new Entry(entry.getDN(), updatedAttributesList);
                        // Преобразуем обновленный Entry в SearchResultEntry
                        SearchResultEntry updatedSearchResultEntry = new SearchResultEntry(updatedEntry);
                        // Преобразуем SearchResultEntry в SearchResultEntryProtocolOp
                        SearchResultEntryProtocolOp entryOp = new SearchResultEntryProtocolOp(updatedSearchResultEntry);
                        // Создаем LDAPMessage с переданным messageID
                        return new LDAPMessage(msgID, entryOp);
                    };
                    ///////// Создаем SearchResultListener с предикатом, messageID и функцией-обработчиком
                    LdapProxyStreamingSearchResultListener listener = new LdapProxyStreamingSearchResultListener(
                        ctx,
                        filter,
                        entryProcessor,
                        messageID
                    );
                    ////////////////////////////////////////////
                    // Выполняем поиск
                    // Выполняем поиск, используя параметры из SearchRequest
                    SearchResult searchResult;
                    try {
                        searchResult = conn.search(
                            listener,
                            searchRequest.getBaseDN(),
                            searchRequest.getScope(),
                            searchRequest.getFilter().toString(),
                            //searchRequest.getAttributes().toArray(new String[0])
                            searchRequest.getAttributes()
                    );
                    } catch (LDAPException e) {
                        logger.error("LDAP search failed: {}", e.getMessage());
                        sendErrorResponse(ctx, messageID, e.getResultCode());
                        return;
                    }
                    // Отправляем SearchResultDone
                    SearchResultDoneProtocolOp doneOp = new SearchResultDoneProtocolOp(
                        new LDAPResult(messageID,searchResult.getResultCode())
                    );
                    LDAPMessage doneMessage = new LDAPMessage(messageID, doneOp);
                    byte[] doneBytes = doneMessage.encode().encode();
                    ByteBuf doneBuf = ctx.alloc().buffer(doneBytes.length);
                    doneBuf.writeBytes(doneBytes);
                    ctx.writeAndFlush(doneBuf);
                    logger.debug("Sent SearchResultDone with messageID: {}", messageID);

                    // Закрываем соединение после отправки SearchResultDone
                    ctx.close();
                    logger.debug("Closed Netty channel after sending SearchResultDone");

                    logger.info("Search completed with result: {}", searchResult.getResultCode());
//                    SearchResult sub;
//                    //sub = conn.search(serverConfig.getBase(), SearchScope.SUB, "(&(sAMAccountName=ivano)(password=Staff1@3))");
//                    sub = conn.search(serverConfig.getBase(), SearchScope.SUB, "(&(sAMAccountName=ivano))");
//                    // Список для хранения всех записей с их атрибутами
//                    List<Map<String, List<String>>> entriesAttributes = new ArrayList<>();
//                    for (SearchResultEntry entry : sub.getSearchEntries()) {
//                        // Карта для хранения атрибутов одной записи (ключ => список значений)
//                        Map<String, List<String>> attributesMap = new HashMap<>();
//
//                        // Извлекаем все атрибуты записи
//                        String sAMAccoutName = entry.getAttributeValue("sAMAccountName");
//                        for (Attribute attr : entry.getAttributes()) {
//                            String attrName = attr.getName();
//                            List<String> attrValues = Arrays.asList(attr.getValues());
//                            attributesMap.put(attrName, attrValues);
//                        }
//                        attributesMap.put("uwedAcMail", List.of(sAMAccoutName + "@uwed.ac.uz"));
//                        attributesMap.put("uwedMail", List.of(sAMAccoutName + "@uwed.uz"));
//                        logger.debug("LDAP attrs are read");
//                        // Добавляем атрибуты записи в список
////                        entriesAttributes.add(entry.getDN(), attributesMap);
//                    }

                } catch (LDAPException e) {
                    logger.debug("LDAP server's " + targetInfo.getUrl() +" operation error: " + e.getMessage());
                    ctx.close();
                }
            }

            logger.debug("LDFAP server " + target + "is bound");
        } else {
            logger.debug("StartTLS handled, waiting for next request");
        }
    }

    private void sendErrorResponse(ChannelHandlerContext ctx, int messageID, ResultCode resultCode) {
        try {
            SearchResultDoneProtocolOp doneOp = new SearchResultDoneProtocolOp( new LDAPResult(messageID, resultCode));
            LDAPMessage doneMessage = new LDAPMessage(messageID, doneOp);
            byte[] doneBytes = doneMessage.encode().encode();
            ByteBuf doneBuf = ctx.alloc().buffer(doneBytes.length);
            doneBuf.writeBytes(doneBytes);
            ctx.writeAndFlush(doneBuf);
            logger.debug("Sent error SearchResultDone with messageID: {}, resultCode: {}", messageID, resultCode);
            ctx.close();
        } catch (Exception e) {
            logger.error("Failed to send error response", e);
            ctx.close();
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
                    return new TargetServerInfo(null, configProperties);
                    //return new TargetServerInfo(null, configProperties, ldapMessage, messageType, messageId, LdapConstants.LDAP_PROTOCOL.LDAP_TLS);
                }
            } else if (messageType == LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST) {
                SearchRequestProtocolOp searchOp = ldapMessage.getSearchRequestProtocolOp();
                String dn = searchOp.getBaseDN();
                for (Map.Entry<String, ConfigProperties.LdapServerConfig> entry : configProperties.getLdapServerConfigs().entrySet()) {
                    if (dn.equals(entry.getValue().getVirtualDn())) {
                        //return new TargetServerInfo(entry.getKey(), configProperties, ldapMessage, messageType, messageId,LdapConstants.LDAP_PROTOCOL.LDAP);
                        return new TargetServerInfo(entry.getKey(), configProperties);
                    }
                }
                logger.warn("No remote LDAP server found for DN: {}", dn);
                //return new TargetServerInfo("dc-01", configProperties, ldapMessage, messageType, messageId,  LdapConstants.LDAP_PROTOCOL.LDAP);
                return new TargetServerInfo("dc-01", configProperties);
            } else if (messageType == LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST) {
                String dn = ldapMessage.getBindRequestProtocolOp().getBindDN();
                for (Map.Entry<String, ConfigProperties.LdapServerConfig> entry : configProperties.getLdapServerConfigs().entrySet()) {
                    if (dn.equals(entry.getValue().getVirtualDn())) {
                        //return new TargetServerInfo(entry.getKey(), configProperties,ldapMessage, messageType, messageId, LdapConstants.LDAP_PROTOCOL.LDAP);
                        return new TargetServerInfo(entry.getKey(), configProperties);
                    }
                }
                logger.warn("No remote LDAP server found for bind DN: {}", dn);
                //return new TargetServerInfo("dc-01", configProperties, ldapMessage, messageType, messageId, LdapConstants.LDAP_PROTOCOL.LDAP);
                return new TargetServerInfo("dc-01", configProperties);
            }
            logger.debug("Unhandled message type: {}", messageType);
            //return new TargetServerInfo("dc-01", configProperties,ldapMessage, messageType, messageId, LdapConstants.LDAP_PROTOCOL.LDAP);
            return new TargetServerInfo("dc-01", configProperties);
        } catch (Exception e) {
            logger.error("Failed to parse LDAP request", e);
            //return new TargetServerInfo("dc-01", configProperties, null, -1, -1, LdapConstants.LDAP_PROTOCOL.LDAP);
            return new TargetServerInfo("dc-01", configProperties);
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
