package edu.uwed.authManager.configuration;

import edu.uwed.authManager.ldap.LdapRequestHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ldap.LdapProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.ldap.core.support.LdapContextSource;

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

    private final ConfigProperties configProperties;
    private final LdapProperties ldapProperties;
//    private final Environment env;

    @Autowired
    public LdapOrmConfig(ConfigProperties configProperties, LdapProperties ldapProperties, Environment env) {
        this.configProperties = configProperties;
//        logger.info("LdapOrmConfig initialized with ConfigProperties servers: {}", configProperties.getLdapServerConfigs());
        this.ldapProperties = ldapProperties;
  //      this.env = env;
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
                contextSource.setBaseEnvironmentProperties(
                        java.util.Collections.singletonMap("java.naming.ldap.starttls", "true")
                );
            }

            if (serverConfig.isIgnoreSslVerification()) {
                SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, new TrustManager[]{
                        new X509TrustManager() {
                            @Override
                            public void checkClientTrusted(X509Certificate[] chain, String authType) {
                            }

                            @Override
                            public void checkServerTrusted(X509Certificate[] chain, String authType) {
                            }

                            @Override
                            public X509Certificate[] getAcceptedIssuers() {
                                return new X509Certificate[0];
                            }
                        }
                }, new SecureRandom());
                contextSource.setBaseEnvironmentProperties(
                        java.util.Collections.singletonMap("java.naming.ldap.factory.socket", "javax.net.ssl.SSLSocketFactory")
                );
                contextSource.setBaseEnvironmentProperties(
                        java.util.Collections.singletonMap("java.naming.ldap.ssl.context", sslContext)
                );
            }

            contextSource.setBaseEnvironmentProperties(
                    java.util.Collections.singletonMap("java.naming.ldap.attributes.binary", "objectGUID objectSid")
            );

            try {
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
