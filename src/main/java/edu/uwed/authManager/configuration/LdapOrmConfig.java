package edu.uwed.authManager.configuration;

import edu.uwed.authManager.ldap.LdapRequestHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.ldap.LdapProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.ldap.core.support.LdapContextSource;

import javax.naming.Context;
import javax.naming.directory.DirContext;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@Configuration
public class LdapOrmConfig {

    private static final Logger logger = LoggerFactory.getLogger(LdapOrmConfig.class);

    private final Map<String, Map<String, Object>> environmentMap = new HashMap<>(); // Локальное хранилище окружения

    private final ConfigProperties configProperties;
    private final LdapProperties ldapProperties;
//    @Bean(name = "outboundLdapTemplates")
    private final Map<String, LdapTemplate> ldapTemplates;
    private final Map<String, SSLContext> outboundSSLContexts; // Внедряем outboundSSLContexts
//    private final Environment env;


    @Autowired
    public LdapOrmConfig(
            ConfigProperties configProperties,
            LdapProperties ldapProperties,
            Environment env,
            @Qualifier("outboundLdapTemplates") Map<String, LdapTemplate> ldapTemplates,
            @Qualifier("outboundSSLContexts") Map<String, SSLContext> outboundSSLContexts
    ) {
        this.configProperties = configProperties;
//        logger.info("LdapOrmConfig initialized with ConfigProperties servers: {}", configProperties.getLdapServerConfigs());
        this.ldapProperties = ldapProperties;
        this.ldapTemplates = ldapTemplates;
        //      this.env = env;
        this.outboundSSLContexts = outboundSSLContexts;
    }

    @Bean(name = "customLdapContextSources")
    public Map<String, BaseLdapPathContextSource> contextSource() throws Exception {
        Map<String, BaseLdapPathContextSource> contextSources = new HashMap<>();
        Map<String, ConfigProperties.LdapServerConfig> serverConfigs = configProperties.getLdapServerConfigs();
        if (serverConfigs.isEmpty()) {
            logger.error("No LDAP server configurations found in ConfigProperties");
            return contextSources;
        }
        for (Map.Entry<String, ConfigProperties.LdapServerConfig> entry : serverConfigs.entrySet()) {
            String serverId = entry.getKey();
            if (ldapTemplates.containsKey(serverId)) {
                BaseLdapPathContextSource contextSource = (BaseLdapPathContextSource) ldapTemplates.get(serverId).getContextSource();
                ConfigProperties.LdapServerConfig serverConfig = entry.getValue();
                // Настройка SSL для LDAPS или startTLS

                // Инициализируем окружение для serverId
                Map<String, Object> env = environmentMap.computeIfAbsent(serverId, k -> new HashMap<>());

                if (serverConfig.isLdaps() || "startTLS".equalsIgnoreCase(serverConfig.getSecurity())) {
                    try {
                        // Используем готовый SSLContext из outboundSSLContexts
                        SSLContext sslContext = outboundSSLContexts.get(serverId);
                        if (sslContext == null) {
                            logger.warn("No SSLContext found for server {}, falling back to default SSL settings", serverId);
                        } else {
                            env.put("java.naming.ldap.factory.socket", sslContext.getSocketFactory().getClass().getName());
                            logger.debug("Configured SSLContext for server {}", serverId);
                        }

                        // Если используется startTLS, включаем его
                        if ("startTLS".equalsIgnoreCase(serverConfig.getSecurity())) {
                            env.put(Context.SECURITY_PROTOCOL, "ssl");
                            logger.debug("Enabled startTLS for server {}", serverId);
                        }

                        // Устанавливаем окружение
                        ((LdapContextSource)contextSource).setBaseEnvironmentProperties(env);
                    } catch (Exception e) {
                        logger.error("Failed to configure SSL for server {}: {}", serverId, e.getMessage(), e);
                    }
                }
                contextSources.put(serverId, contextSource);
            } else {
                logger.error("No LDAP template found for server " + serverId);
            }

        }
/**
 //          Настройка SSL для LDAPS или startTLS
 //            if (config.isLdaps() || "startTLS".equalsIgnoreCase(config.getSecurity())) {
 //                try {
 //                    // Используем готовый SSLContext из outboundSSLContexts
 //                    SSLContext sslContext = outboundSSLContexts.get(serverId);
 //                    if (sslContext == null) {
 //                        logger.warn("No SSLContext found for server {}, falling back to default SSL settings", serverId);
 //                    } else {
 //                        env.put("java.naming.ldap.factory.socket", sslContext.getSocketFactory().getClass().getName());
 //                        logger.debug("Configured SSLContext for server {}", serverId);
 //                    }
 //
 //                    // Если используется startTLS, включаем его
 //                    if ("startTLS".equalsIgnoreCase(config.getSecurity())) {
 //                        env.put(Context.SECURITY_PROTOCOL, "ssl");
 //                        logger.debug("Enabled startTLS for server {}", serverId);
 //                    }
 //
 //                    // Устанавливаем окружение
 //                    contextSource.setBaseEnvironmentProperties(env);
 //                } catch (Exception e) {
 //                    logger.error("Failed to configure SSL for server {}: {}", serverId, e.getMessage(), e);
 //                }
 //            }
 */



//        for (Map.Entry<String, ConfigProperties.LdapServerConfig> entry : serverConfigs.entrySet()) {
//            String serverId = entry.getKey();
//            ConfigProperties.LdapServerConfig serverConfig = entry.getValue();
//
//            String host = serverConfig.getHost();
//            int port = serverConfig.isLdaps() ? serverConfig.getLdapsPort() : serverConfig.getLdapPort();
//            String url = serverConfig.getUrl();
//            String userDn = serverConfig.getUserDn();
//            String userPassword = serverConfig.getPassword();
//
//            logger.info("Configuring LdapContextSource for server {}: url={}", serverId, url);
//
//            LdapContextSource contextSource = new LdapContextSource();
//            contextSource.setUrl(url);
//            contextSource.setBase(serverConfig.getBase());
//            contextSource.setUserDn(userDn);
//            contextSource.setPassword(userPassword);
//            contextSource.setPooled(false);
//            contextSource.setAnonymousReadOnly(false);
//            contextSource.setReferral(serverConfig.getReferralHandling());
//
//            try {
//                logger.info("Preparing LdapContextSource for server {}", serverId);
//                contextSource.afterPropertiesSet();
//                contextSources.put(serverId, contextSource);
//                logger.info("LdapContextSource prepared successfully for server {}", serverId);
//            } catch (Exception e) {
//                logger.error("Failed to initialize LdapContextSource for server {}: url={}", serverId, url, e);
//            }
//        }

        return contextSources;
    }

    /// /////////////////////////////
    public Map<String, BaseLdapPathContextSource> ___contextSource() throws Exception {
        Map<String, BaseLdapPathContextSource> contextSources = new HashMap<>();

        Map<String, ConfigProperties.LdapServerConfig> serverConfigs = configProperties.getLdapServerConfigs();
//        logger.debug("LDAP server configs: {}", serverConfigs);
        if (serverConfigs.isEmpty()) {
            logger.error("No LDAP server configurations found in ConfigProperties");
            return contextSources;
        }

        // Добавляем отладочный лог
  //      logger.debug("LDAP server configs: {}", configProperties.getLdapServerConfigs());
        for (Map.Entry<String, ConfigProperties.LdapServerConfig> entry :
                serverConfigs.entrySet())
        {
            String serverId = entry.getKey();
            ConfigProperties.LdapServerConfig serverConfig = entry.getValue();

            LdapContextSource contextSource = new LdapContextSource();
            contextSource.setUrl(serverConfig.getUrl());
            contextSource.setBase(serverConfig.getBase());
            contextSource.setUserDn(serverConfig.getUserDn());
            contextSource.setPassword(serverConfig.getPassword());
            contextSource.setPooled(false);
            contextSource.setAnonymousReadOnly(false);
            contextSource.setReferral(serverConfig.getReferralHandling());

            if (serverConfig.isStartTls()) {
                ldapProperties.getBaseEnvironment().put("java.naming.ldap.starttls", "true");
//                contextSource.setBaseEnvironmentProperties(
//                    java.util.Collections.singletonMap("java.naming.ldap.starttls", "true")
//                );
            }

            if (serverConfig.isIgnoreSslVerification()) {
                ldapProperties.getBaseEnvironment().put("java.naming.ldap.factory.socket", DummySSLSocketFactory.class.getName());
//                contextSource.setBaseEnvironmentProperties(Collections.unmodifiableMap(ldapProperties.getBaseEnvironment()));

//                SSLContext sslContext = SSLContext.getInstance("TLS");
//                sslContext.init(null, new TrustManager[]{
//                    new X509TrustManager() {
//                        @Override
//                        public void checkClientTrusted(X509Certificate[] chain, String authType) {
//                        }
//
//                        @Override
//                        public void checkServerTrusted(X509Certificate[] chain, String authType) {
//                        }
//
//                        @Override
//                        public X509Certificate[] getAcceptedIssuers() {
//                            return new X509Certificate[0];
//                        }
//                    }
//                }, new SecureRandom());
//                contextSource.setBaseEnvironmentProperties(
//                    java.util.Collections.singletonMap("java.naming.ldap.factory.socket", "javax.net.ssl.SSLSocketFactory")
//                );
//                contextSource.setBaseEnvironmentProperties(
//                    java.util.Collections.singletonMap("java.naming.ldap.ssl.context", sslContext)
//                );
            }

            contextSource.setBaseEnvironmentProperties(
//////////                ldapProperties.getBaseEnvironment().put("java.naming.ldap.attributes.binary", "objectGUID objectSid");
                java.util.Collections.singletonMap("java.naming.ldap.attributes.binary", "objectGUID objectSid")
            );

//////////            contextSource.setBaseEnvironmentProperties(Collections.unmodifiableMap(ldapProperties.getBaseEnvironment()));

            try {
                // propagate properties changes if occured
                contextSource.afterPropertiesSet();
                logger.debug("Successfully initialized LdapContextSource for server: {}", serverId);
            } catch (Exception e) {
                logger.error("Failed to initialize LdapContextSource for server: {}", serverId, e);
                throw new RuntimeException("Failed to initialize LdapContextSource for " + serverId, e);
            }

            contextSources.put(serverId, contextSource);
        }

        return contextSources;
    }
}
