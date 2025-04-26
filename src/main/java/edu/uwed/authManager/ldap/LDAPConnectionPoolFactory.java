package edu.uwed.authManager.ldap;

import com.unboundid.ldap.sdk.*;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import edu.uwed.authManager.configuration.ConfigProperties;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import javax.net.ssl.SSLSocketFactory;

@Component
public class LDAPConnectionPoolFactory {
    private static final Logger logger = LoggerFactory.getLogger(LDAPConnectionPoolFactory.class);
    private final ConfigProperties configProperties;
    private final SSLSocketFactory socketFactory;
    private volatile LDAPConnectionPool connectionPool;

    @Autowired
    public LDAPConnectionPoolFactory(
            ConfigProperties configProperties,
            @Qualifier("targetLdapSecureSocketFactory") SSLSocketFactory socketFactory
    ) {
        this.configProperties = configProperties;
        this.socketFactory = socketFactory;
    }

    public synchronized LDAPConnectionPool getConnectionPool(TargetServerInfo targetServerInfo) throws LDAPException {
        if (connectionPool == null || connectionPool.isClosed()) {
            logger.info("Creating new LDAPConnectionPool for {}:{} (protocol: {})",
                    targetServerInfo.getHost(), targetServerInfo.getPort(), targetServerInfo.getProto());

            LDAPConnection connection = getLdapConnection(
                    targetServerInfo.getProto(),
                    targetServerInfo.getHost(),
                    targetServerInfo.getPort(),
                    socketFactory
            );
            try {
                long startTime = System.currentTimeMillis();
                // НЕ выполняем bind здесь, чтобы соединение оставалось непривязанным
                connectionPool = new LDAPConnectionPool(
                        connection,
                        1,
                        configProperties.getTargetConfig().getPoolMaxConnections(),
                        3,
                        null,
                        true
                );
                logger.info("LDAPConnectionPool created successfully for {}:{} (protocol: {}) in {} ms",
                        targetServerInfo.getHost(), targetServerInfo.getPort(), targetServerInfo.getProto(),
                        System.currentTimeMillis() - startTime);
            } catch (LDAPException e) {
                connection.close();
                logger.error("Failed to create LDAPConnectionPool for {}:{}: {}",
                        targetServerInfo.getHost(), targetServerInfo.getPort(), e.getMessage(), e);
                throw e;
            }
        } else {
            logger.debug("Reusing existing LDAPConnectionPool for {}:{} (protocol: {})",
                    targetServerInfo.getHost(), targetServerInfo.getPort(), targetServerInfo.getProto());
        }
        return connectionPool;
    }

    private LDAPConnection getLdapConnection(
            LdapConstants.LDAP_PROTOCOL protocol,
            String host,
            int port,
            SSLSocketFactory socketFactory
    ) throws LDAPException {
        LDAPConnection connection = null;
        switch (protocol) {
            case LDAP:
                connection = new LDAPConnection(host, port);
                logger.debug("Created LDAP connection for {}:{}", host, port);
                return connection;
            case LDAPS:
                connection = new LDAPConnection(socketFactory, host, port);
                logger.debug("Created LDAPS connection for {}:{}", host, port);
                return connection;
            case LDAP_TLS:
                connection = new LDAPConnection(host, port);
                ExtendedResult startTLSResult = connection.processExtendedOperation(
                        new StartTLSExtendedRequest(socketFactory)
                );
                if (!startTLSResult.getResultCode().isConnectionUsable()) {
                    logger.warn("StartTLS operation failed for server {}:{}", host, port);
                    connection.close();
                    throw new LDAPException(ResultCode.CONNECT_ERROR, "StartTLS failed");
                }
                logger.debug("Created LDAP+StartTLS connection for {}:{}", host, port);
                return connection;
            default:
                throw new IllegalArgumentException("Unsupported protocol: " + protocol);
        }
    }

    public synchronized void invalidateConnection(LDAPConnection connection) {
        if (connectionPool != null && connection != null) {
            logger.info("Invalidating LDAP connection: {}", connection);
            connectionPool.releaseDefunctConnection(connection);
            // Пул автоматически создаст новое соединение, если createIfNecessary=true
        }
    }

    @PreDestroy
    public void close() {
        if (connectionPool != null) {
            connectionPool.close();
            logger.info("LDAPConnectionPool closed");
        }
    }
}
