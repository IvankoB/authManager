package edu.uwed.authManager.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.ldap.core.support.LdapContextSource;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

@Configuration
public class LdapOrmConfig {
    private final ConfigProperties configProperties;

    @Autowired
    public LdapOrmConfig(ConfigProperties configProperties) {
        this.configProperties = configProperties;
    }

    @Bean
    public Map<String, BaseLdapPathContextSource> contextSource() throws Exception {
        Map<String, BaseLdapPathContextSource> contextSources = new HashMap<>();

        for (Map.Entry<String, ConfigProperties.LdapServerConfig> entry :
            configProperties.getLdapServerConfigs().entrySet())
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
                // propagate properties changes if occured
                contextSource.afterPropertiesSet();
            } catch (Exception e) {
                throw new RuntimeException("Failed to initialize LdapContextSource for " + serverId, e);
            }

            contextSources.put(serverId, contextSource);
        }

        return contextSources;
    }
}
