package edu.uwed.authManager.services;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.SearchRequestProtocolOp;
import com.unboundid.ldap.protocol.SearchResultEntryProtocolOp;
import edu.uwed.authManager.configuration.ConfigProperties;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.ssl.SslContext;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.stereotype.Service;

import javax.naming.directory.Attributes;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class LdapRequestHandler {

    @Getter
    private final Map<String, LdapTemplate> ldapTemplates;

    @Getter
    private final SslContext sslContext;

    @Getter
    private final ConfigProperties configProperties;

    private final Map<ChannelHandlerContext, String> authenticatedDns = new ConcurrentHashMap<>();

    public LdapRequestHandler(
            Map<String, LdapTemplate> ldapTemplates,
            @Qualifier("dc01LdapProxySslContext") SslContext sslContext,
            ConfigProperties configProperties
    ) {
        this.ldapTemplates = ldapTemplates;
        this.sslContext = sslContext;
        this.configProperties = configProperties;
        System.out.println("LdapRequestHandler initialized with proxy users: " + configProperties.getProxyUsers());
    }

    public void handleRequest(ChannelHandlerContext ctx, ByteBuf msg, boolean isLdaps) throws Exception {
        System.out.println("LdapProxyServer (" + (isLdaps ? "LDAPS" : "LDAP") + "): Received message, readable bytes=" + msg.readableBytes() + ", ctx=" + ctx);

        ConfigProperties.ProxyConfig proxyConfig = configProperties.getProxyConfig();
        int maxMessageSize = proxyConfig.getMaxMessageSize();

        if (msg.readableBytes() > maxMessageSize) {
            throw new IllegalArgumentException("Message size exceeds maximum allowed: " + msg.readableBytes() + " > " + maxMessageSize);
        }
        byte[] bytes = new byte[msg.readableBytes()];
        msg.readBytes(bytes);
        StringBuilder hexDump = new StringBuilder();
        for (byte b : bytes) {
            hexDump.append(String.format("%02x ", b));
        }
        System.out.println("LdapProxyServer (" + (isLdaps ? "LDAPS" : "LDAP") + "): Raw message bytes=" + hexDump.toString());

        LDAPMessage ldapMessage = null;
        try {
            ASN1StreamReader asn1Reader = new ASN1StreamReader(new ByteArrayInputStream(bytes));
            ldapMessage = LDAPMessage.readFrom(asn1Reader, true);
            System.out.println("LdapProxyServer (" + (isLdaps ? "LDAPS" : "LDAP") + "): Message ID=" + ldapMessage.getMessageID() + ", ProtocolOpType=" + ldapMessage.getProtocolOpType() + ", ctx=" + ctx);

            if (ldapMessage.getProtocolOpType() == LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST) {
                handleBindRequest(ctx, ldapMessage, isLdaps);
            } else if (ldapMessage.getProtocolOpType() == LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST) {
                handleSearchRequest(ctx, ldapMessage, isLdaps);
            } else if (ldapMessage.getProtocolOpType() == LDAPMessage.PROTOCOL_OP_TYPE_UNBIND_REQUEST) {
                System.out.println("LdapProxyServer (" + (isLdaps ? "LDAPS" : "LDAP") + "): Received UnbindRequest, closing connection, ctx=" + ctx);
                authenticatedDns.remove(ctx);
                ctx.close();
            } else {
                System.out.println("LdapProxyServer (" + (isLdaps ? "LDAPS" : "LDAP") + "): Unsupported operation: " + ldapMessage.getProtocolOpType() + ", ctx=" + ctx);
                ctx.writeAndFlush(createErrorResponse(ctx, ldapMessage.getMessageID(), 2)); // protocolError
            }
        } catch (Exception e) {
            System.err.println("LdapProxyServer (" + (isLdaps ? "LDAPS" : "LDAP") + "): Failed to decode message: " + e.getMessage() + ", ctx=" + ctx);
            ByteBuf errorResponse = ctx.alloc().buffer();
            errorResponse.writeBytes(new byte[]{
                    0x30, 0x0c, 0x02, 0x01, (byte) (ldapMessage != null ? ldapMessage.getMessageID() : 1), // Message ID (если доступен)
                    0x61, 0x07, 0x0a, 0x01, 0x32, // BindResponse, resultCode=50 (insufficientAccessRights)
                    0x04, 0x00, 0x04, 0x00        // matchedDN и diagnosticMessage пустые
            });
            ctx.writeAndFlush(errorResponse);
        }
    }
    private void handleBindRequest(ChannelHandlerContext ctx, LDAPMessage ldapMessage, boolean isLdaps) {
        String dn = ldapMessage.getBindRequestProtocolOp().getBindDN();
        ASN1OctetString passwordObj = ldapMessage.getBindRequestProtocolOp().getSimplePassword();
        String passwordStr = passwordObj != null ? new String(passwordObj.getValue(), StandardCharsets.UTF_8) : "";
        System.out.println("LdapProxyServer (" + (isLdaps ? "LDAPS" : "LDAP") + "): Bind DN=" + dn + ", Password=" + passwordStr + ", ctx=" + ctx);

        boolean authSuccess = configProperties.getProxyUsers().stream()
                .anyMatch(user -> {
                    boolean match = user.getDn().equalsIgnoreCase(dn) && user.getPassword().equals(passwordStr);
                    System.out.println("LdapProxyServer (" + (isLdaps ? "LDAPS" : "LDAP") + "): Checking user - DN=" + user.getDn() + ", Password=" + user.getPassword() + ", match=" + match);
                    return match;
                });
        System.out.println("LdapProxyServer (" + (isLdaps ? "LDAPS" : "LDAP") + "): Bind " + (authSuccess ? "successful" : "failed") + ", ctx=" + ctx);

        ByteBuf response = ctx.alloc().buffer();
        if (authSuccess) {
            authenticatedDns.put(ctx, dn);
            System.out.println("LdapProxyServer (" + (isLdaps ? "LDAPS" : "LDAP") + "): Stored authenticated DN=" + dn + " for ctx=" + ctx);
            response.writeBytes(new byte[]{
                    0x30, 0x0c, 0x02, 0x01, (byte) ldapMessage.getMessageID(), // Message ID
                    0x61, 0x07, 0x0a, 0x01, 0x00, // BindResponse, resultCode=success
                    0x04, 0x00, 0x04, 0x00        // matchedDN и diagnosticMessage пустые
            });
        } else {
            authenticatedDns.remove(ctx);
            System.out.println("LdapProxyServer (" + (isLdaps ? "LDAPS" : "LDAP") + "): Authentication failed, no DN stored for ctx=" + ctx);
            response.writeBytes(new byte[]{
                    0x30, 0x0c, 0x02, 0x01, (byte) ldapMessage.getMessageID(), // Message ID
                    0x61, 0x07, 0x0a, 0x01, 0x31, // BindResponse, resultCode=49 (invalidCredentials)
                    0x04, 0x00, 0x04, 0x00        // matchedDN и diagnosticMessage пустые
            });
        }
        ctx.writeAndFlush(response);
        System.out.println("LdapProxyServer (" + (isLdaps ? "LDAPS" : "LDAP") + "): Sent Bind response, ctx=" + ctx);
    }
    private void handleSearchRequest(ChannelHandlerContext ctx, LDAPMessage ldapMessage, boolean isLdaps) {
        System.out.println("LdapProxyServer (" + (isLdaps ? "LDAPS" : "LDAP") + "): Processing SearchRequest, ctx=" + ctx);
        SearchRequestProtocolOp searchOp = ldapMessage.getSearchRequestProtocolOp();
        String authenticatedDn = authenticatedDns.get(ctx);
        System.out.println("LdapProxyServer (" + (isLdaps ? "LDAPS" : "LDAP") + "): Authenticated DN=" + authenticatedDn + ", ctx=" + ctx);

        if (authenticatedDn == null) {
            System.out.println("LdapProxyServer (" + (isLdaps ? "LDAPS" : "LDAP") + "): Search rejected - no authenticated user, ctx=" + ctx);
            ctx.writeAndFlush(createErrorResponse(ctx, ldapMessage.getMessageID(), 50));
            return;
        }

        String clientBaseDn = searchOp.getBaseDN();
        String targetServer = null;
        ConfigProperties.LdapServerConfig targetConfig = null;
        for (Map.Entry<String, ConfigProperties.LdapServerConfig> entry : configProperties.getLdapServerConfigs().entrySet()) {
            String serverName = entry.getKey();
            ConfigProperties.LdapServerConfig config = entry.getValue();
            if (clientBaseDn.equalsIgnoreCase(config.getVirtualDn())) {
                targetServer = serverName;
                targetConfig = config;
                break;
            }
        }

        if (targetServer == null) {
            System.out.println("LdapProxyServer (" + (isLdaps ? "LDAPS" : "LDAP") + "): No server found for base DN: " + clientBaseDn);
            ctx.writeAndFlush(createErrorResponse(ctx, ldapMessage.getMessageID(), 32));
            return;
        }

        LdapTemplate ldapTemplate = ldapTemplates.get(targetServer);
        if (ldapTemplate == null) {
            System.out.println("LdapProxyServer (" + (isLdaps ? "LDAPS" : "LDAP") + "): No LdapTemplate for server: " + targetServer);
            ctx.writeAndFlush(createErrorResponse(ctx, ldapMessage.getMessageID(), 80));
            return;
        }

        Optional<ConfigProperties.ProxyUser> userOpt = configProperties.getProxyUsers().stream()
                .filter(user -> user.getDn().equalsIgnoreCase(authenticatedDn))
                .findFirst();
        if (userOpt.isEmpty()) {
            System.out.println("LdapProxyServer (" + (isLdaps ? "LDAPS" : "LDAP") + "): User not found: " + authenticatedDn);
            ctx.writeAndFlush(createErrorResponse(ctx, ldapMessage.getMessageID(), 50));
            return;
        }

        ConfigProperties.ProxyUser user = userOpt.get();
        boolean isBaseDnAllowed = user.getAllowedDns().stream()
                .anyMatch(dn -> dn.equalsIgnoreCase("[*]") || dn.equalsIgnoreCase(clientBaseDn));
        if (!isBaseDnAllowed) {
            System.out.println("LdapProxyServer (" + (isLdaps ? "LDAPS" : "LDAP") + "): Search base=" + clientBaseDn + " not allowed for " + authenticatedDn);
            ctx.writeAndFlush(createErrorResponse(ctx, ldapMessage.getMessageID(), 50));
            return;
        }

        String mappedBaseDn = clientBaseDn.equalsIgnoreCase(targetConfig.getVirtualDn()) ? targetConfig.getBase() : clientBaseDn;
        System.out.println("LdapProxyServer (" + (isLdaps ? "LDAPS" : "LDAP") + "): Search base=" + clientBaseDn + " mapped to " + mappedBaseDn + ", filter=" + searchOp.getFilter() + ", server=" + targetServer);

        List<ByteBuf> responses = new ArrayList<>();
        try {
            System.out.println("LdapProxyServer (" + (isLdaps ? "LDAPS" : "LDAP") + "): Starting search on " + targetServer);
            long startTime = System.currentTimeMillis();
            List<Object> results = ldapTemplate.search(
                    mappedBaseDn,
                    searchOp.getFilter().toString(),
                    (AttributesMapper<Object>) Attributes::toString
            );
            long endTime = System.currentTimeMillis();
            System.out.println("LdapProxyServer (" + (isLdaps ? "LDAPS" : "LDAP") + "): Search completed, results=" + results.size() + ", took=" + (endTime - startTime) + "ms");

            for (Object result : results) {
                if (result instanceof String entry) {
                    SearchResultEntryProtocolOp entryOp = new SearchResultEntryProtocolOp(entry, new ArrayList<>());
                    byte[] entryBytes = entryOp.encodeProtocolOp().encode();
                    ByteBuf entryBuf = createLdapMessage(ctx, ldapMessage.getMessageID(), entryBytes);
                    responses.add(entryBuf);
                    System.out.println("LdapProxyServer (" + (isLdaps ? "LDAPS" : "LDAP") + "): Added entry: " + entry);
                }
            }
        } catch (Exception e) {
            System.err.println("LdapProxyServer (" + (isLdaps ? "LDAPS" : "LDAP") + "): Search failed on " + targetServer + ": " + e.getMessage());
            ctx.writeAndFlush(createErrorResponse(ctx, ldapMessage.getMessageID(), 80));
            return;
        }

        byte[] doneBytes = new byte[]{0x65, 0x00}; // SearchResultDone, resultCode=success
        ByteBuf doneResponse = createLdapMessage(ctx, ldapMessage.getMessageID(), doneBytes);
        responses.add(doneResponse);
        System.out.println("LdapProxyServer (" + (isLdaps ? "LDAPS" : "LDAP") + "): Prepared SearchResultDone");

        for (ByteBuf response : responses) {
            ctx.writeAndFlush(response);
            System.out.println("LdapProxyServer (" + (isLdaps ? "LDAPS" : "LDAP") + "): Sent response");
        }
        System.out.println("LdapProxyServer (" + (isLdaps ? "LDAPS" : "LDAP") + "): All responses sent");
    }

    private ByteBuf createLdapMessage(ChannelHandlerContext ctx, int messageId, byte[] protocolOpBytes) {
        ByteBuf buf = ctx.alloc().buffer();
        buf.writeByte(0x30); // SEQUENCE
        buf.writeByte(protocolOpBytes.length + 3); // Длина: Message ID (3 байта) + данные
        buf.writeByte(0x02); // INTEGER
        buf.writeByte(0x01); // Длина 1
        buf.writeByte((byte) messageId); // Message ID
        buf.writeBytes(protocolOpBytes);
        return buf;
    }

    private ByteBuf createErrorResponse(ChannelHandlerContext ctx, int messageId, int resultCode) {
        byte[] errorBytes = new byte[]{
                0x65, 0x07,           // SearchResultDone, длина 7 байт
                0x0a, 0x01, (byte) resultCode, // resultCode
                0x04, 0x00,           // matchedDN (пусто)
                0x04, 0x00            // diagnosticMessage (пусто)
        };
        return createLdapMessage(ctx, messageId, errorBytes);
    }
}
