package edu.uwed.authManager.configuration;

import edu.uwed.authManager.ldap.LdapProxyServer;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.ldap.core.LdapTemplate;

import javax.naming.Context;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;

import edu.uwed.authManager.ldap.LdapRequestHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Configuration
//@RequiredArgsConstructor
public class LdapConfig {

    private static final Logger logger = LoggerFactory.getLogger(LdapProxyServer.class);

    // beans to autowire by the @RequiredArgs-ed Constructor
    private final SslBundles sslBundles;
    private final ConfigProperties configProperties;

    @Autowired
    public LdapConfig(SslBundles sslBundles, ConfigProperties configProperties) {
        this.sslBundles = sslBundles;
        this.configProperties = configProperties;
    }

    @Bean(name = "ldaps") // Переименовали
    public SslContext ldaps() throws Exception {
        SslBundle sslBundle = sslBundles.getBundle("ldaps");
        KeyStore keyStore = sslBundle.getStores().getKeyStore();
        String keyPassword = sslBundle.getKey().getPassword();
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, keyPassword != null ? keyPassword.toCharArray() : null);

        KeyStore trustStore = sslBundle.getStores().getTrustStore();
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);
        return SslContextBuilder
                .forServer(keyManagerFactory)
                .trustManager(trustManagerFactory)
                .build();
    }

    @Bean(name = "startTlsSslContext")
    public SSLContext startTlsSslContext() throws Exception {
        SslBundle sslBundle = sslBundles.getBundle("ldaps"); // Для входящих StartTLS
        KeyStore keyStore = sslBundle.getStores().getKeyStore();
        String keyPassword = sslBundle.getKey().getPassword();
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, keyPassword != null ? keyPassword.toCharArray() : null);
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), null, null);
        logger.debug("Created Java SSLContext for StartTLS with alias: {}", keyStore.aliases().nextElement());
        return sslContext;
    }

    @Bean
    public Map<String, SslContext> ldapProxySslContexts() throws Exception {
        Map<String, SslContext> sslContexts = new HashMap<>();

        // Проходим по всем серверам из ConfigProperties
        Map<String, ConfigProperties.LdapServerConfig> servers = configProperties.getLdapServerConfigs();
        for (String serverName : servers.keySet()) {
            String bundleName = servers.get(serverName).getSslBundle();
            SslBundle sslBundle = sslBundles.getBundle(bundleName);

            KeyStore keyStore = sslBundle.getStores().getKeyStore();
            String keyPassword = sslBundle.getKey().getPassword();
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, keyPassword != null ? keyPassword.toCharArray() : null);

            KeyStore trustStore = sslBundle.getStores().getTrustStore();
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);

            SslContext sslContext = SslContextBuilder
                    .forServer(keyManagerFactory)
                    .trustManager(trustManagerFactory)
                    .build();

            sslContexts.put(serverName, sslContext); // Ключ — имя сервера ("dc-01", "dc-02")
        }

        return sslContexts;
    }

    @Bean
    public Map<String, SSLContext> outgoingSslContexts() throws Exception {
        Map<String, SSLContext> sslContexts = new HashMap<>();
        for (Map.Entry<String, ConfigProperties.LdapServerConfig> entry : configProperties.getLdapServerConfigs().entrySet()) {
            String serverName = entry.getKey();
            String sslBundleName = entry.getValue().getSslBundle();
            if (sslBundleName != null) {
                SslBundle sslBundle = sslBundles.getBundle(sslBundleName);
                KeyStore keyStore = sslBundle.getStores().getKeyStore();
                String keyPassword = sslBundle.getKey().getPassword();
                KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                kmf.init(keyStore, keyPassword != null ? keyPassword.toCharArray() : null);
                KeyStore trustStore = sslBundle.getStores().getTrustStore();
                TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(trustStore);
                SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
                sslContexts.put(serverName, sslContext);
                logger.debug("Created outgoing Java SSLContext for server: {}", serverName);
            }
        }
        return sslContexts;
    }

    @Bean
    public Map<String, LdapTemplate> ldapTemplates() throws Exception {
        Map<String, LdapTemplate> templates = new HashMap<>();
        for (Map.Entry<String, ConfigProperties.LdapServerConfig> entry : configProperties.getLdapServerConfigs().entrySet()) {
            String serverName = entry.getKey();
            ConfigProperties.LdapServerConfig config = entry.getValue();

            LdapContextSource contextSource = new LdapContextSource();
            contextSource.setUrl(config.getUrl());
            contextSource.setUserDn(config.getUserDn());
            contextSource.setPassword(config.getPassword());
            contextSource.setBase(config.getBase());
            System.out.println("LdapConfig: Connecting to " + config.getUrl() + " with user " + config.getUserDn());

            Map<String, Object> env = new HashMap<>();
            boolean isLdaps = config.getUrl().toLowerCase().startsWith("ldaps://");
            if (config.isStartTls() && !isLdaps) {
                env.put("java.naming.ldap.starttls", "true");
                env.put("java.naming.ldap.starttls.required", String.valueOf(config.isStartTlsRequired()));
            }

            String referralHandling = config.getReferralHandling();
            if (referralHandling != null && !referralHandling.isEmpty()) {
                if ("follow".equalsIgnoreCase(referralHandling) || "ignore".equalsIgnoreCase(referralHandling) || "throw".equalsIgnoreCase(referralHandling)) {
                    env.put(Context.REFERRAL, referralHandling.toLowerCase());
                    System.out.println("LdapConfig: Referral handling set to " + referralHandling + " for server " + serverName);
                } else {
                    System.err.println("LdapConfig: Invalid referralHandling value '" + referralHandling + "' for server " + serverName + ". Using default 'follow'.");
                    env.put(Context.REFERRAL, "follow");
                }
            } else {
                env.put(Context.REFERRAL, "follow");
                System.out.println("LdapConfig: Using default referral handling 'follow' for server " + serverName);
            }
            env.put("com.sun.jndi.ldap.connect.timeout", "10000");
            env.put("com.sun.jndi.ldap.read.timeout", "30000");
            contextSource.setBaseEnvironmentProperties(env);

            System.out.println("LdapConfig: Attempting to initialize context for " + config.getUrl());
            contextSource.afterPropertiesSet();
            System.out.println("LdapConfig: Context initialized successfully for " + config.getUrl());

            templates.put(serverName, new LdapTemplate(contextSource));
        }
        return templates;
    }

    @Bean(name = "dc-01")
    public ConfigProperties.LdapServerConfig dc01ServerConfig() {
        return configProperties.getLdapServerConfigs().get("dc-01");
    }
}
