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
import javax.net.ssl.*;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;

import edu.uwed.authManager.ldap.LdapRequestHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Configuration
//@RequiredArgsConstructor
public class LdapConfig {

    private static final Logger logger = LoggerFactory.getLogger(LdapProxyServer.class);

    private final SslBundles sslBundles;
    private final ConfigProperties configProperties;
//    private final Map<String, SSLContext> outboundSSLContexts;
//    private final Map<String, Map<String, Object>> environmentMap = new HashMap<>(); // Локальное хранилище окружения

    @Autowired
    public LdapConfig(
            SslBundles sslBundles,
            ConfigProperties configProperties //,
//            Map<String, SSLContext> outboundSSLContexts
    ) {
        this.sslBundles = sslBundles;
        this.configProperties = configProperties;
//        this.outboundSSLContexts = outboundSSLContexts;
    }

    @Bean(name = "ldaps")
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
        SslBundle sslBundle = sslBundles.getBundle("ldaps");
        KeyStore keyStore = sslBundle.getStores().getKeyStore();
        String keyPassword = sslBundle.getKey().getPassword();
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, keyPassword != null ? keyPassword.toCharArray() : null);
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), null, null);
        logger.debug("Created Java SSLContext for StartTLS with alias: {}", keyStore.aliases().nextElement());
        return sslContext;
    }

    @Bean(name = "outboundSslContexts")
    public Map<String, SslContext> proxySslContexts() throws Exception {
        Map<String, SslContext> sslContexts = new HashMap<>();
        SslContext defaultLdapsContext = ldaps();
        sslContexts.put("ldaps", defaultLdapsContext);
        logger.debug("Added fallback 'ldaps' to proxySslContexts");

        for (Map.Entry<String, ConfigProperties.LdapServerConfig> entry : configProperties.getLdapServerConfigs().entrySet()) {
            String serverName = entry.getKey();
            ConfigProperties.LdapServerConfig config = entry.getValue();
            String bundleName = config.getSslBundle();

            if (bundleName != null && !bundleName.equals("ldaps") && sslBundles.getBundleNames().contains(bundleName)) {
                SslBundle sslBundle = sslBundles.getBundle(bundleName);
                KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                kmf.init(sslBundle.getStores().getKeyStore(), sslBundle.getKey().getPassword() != null ? sslBundle.getKey().getPassword().toCharArray() : null);
                TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(sslBundle.getStores().getTrustStore());

                SslContextBuilder builder = SslContextBuilder
                        .forClient()
                        .keyManager(kmf)
                        .trustManager(tmf);

                if (config.getSslProtocols() != null && !config.getSslProtocols().isEmpty()) {
                    List<String> protocols = Arrays.stream(config.getSslProtocols().split(","))
                            .map(String::trim)
                            .filter(s -> !s.isEmpty())
                            .collect(Collectors.toList());
                    builder.protocols(protocols);
                    logger.debug("Set protocols for {}: {}", serverName, protocols);
                }

                if (config.getSslCiphers() != null && !config.getSslCiphers().isEmpty()) {
                    List<String> ciphers = Arrays.stream(config.getSslCiphers().split(","))
                            .map(String::trim)
                            .filter(s -> !s.isEmpty())
                            .collect(Collectors.toList());
                    builder.ciphers(ciphers);
                    logger.debug("Set ciphers for {}: {}", serverName, ciphers);
                }

                SslContext sslContext = builder.build();
                sslContexts.put(serverName, sslContext);
                logger.debug("Initialized SslContext for server: {}", serverName);
            }
        }
        logger.info("proxySslContexts initialized with keys: {}", sslContexts.keySet());
        return sslContexts;
    }

    @Bean(name = "outboundSSLContexts")
    public Map<String, SSLContext> outgoingSslContexts() throws Exception {
        Map<String, SSLContext> sslContexts = new HashMap<>();
        for (Map.Entry<String, ConfigProperties.LdapServerConfig> entry : configProperties.getLdapServerConfigs().entrySet()) {
            String serverName = entry.getKey();
            ConfigProperties.LdapServerConfig config = entry.getValue();
            String bundleName = config.getSslBundle();

            if (bundleName != null && sslBundles.getBundleNames().contains(bundleName)) {
                SslBundle sslBundle = sslBundles.getBundle(bundleName);
                SSLContext sslContext = SSLContext.getInstance("TLS");
                TrustManager[] trustManagers = config.isIgnoreSslVerification() ?
                    new TrustManager[]{new X509TrustManager() {
                        public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                        public void checkServerTrusted(X509Certificate[] chain, String authType) {}
                        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    }} : sslBundle.getManagers().getTrustManagers();
                sslContext.init(
                        sslBundle.getManagers().getKeyManagers(),
                        trustManagers,
                        new java.security.SecureRandom()
                );

                sslContexts.put(serverName, sslContext);
                logger.debug("Created outgoing SSLContext for server: {}", serverName);
            }
        }
        logger.info("outgoingSslContexts initialized with keys: {}", sslContexts.keySet());
        return sslContexts;
    }

    @Bean(name = "outboundLdapTemplates")
    public Map<String, LdapTemplate> ldapTemplates() throws Exception {
        Map<String, LdapTemplate> templates = new HashMap<>();
        for (Map.Entry<String, ConfigProperties.LdapServerConfig> entry : configProperties.getLdapServerConfigs().entrySet()) {
            String serverId = entry.getKey();
            ConfigProperties.LdapServerConfig config = entry.getValue();

            String host = config.getHost();
            int port = config.isLdaps() ? config.getLdapsPort() : config.getLdapPort();
            String url = config.getUrl();
            String userDn = config.getUserDn();
            String userPassword = config.getPassword();

            logger.info("Configuring LDAP template for server {}: url={}", serverId, url);

            LdapContextSource contextSource = new LdapContextSource();
            contextSource.setUrl(url);
            contextSource.setUserDn(userDn);
            contextSource.setPassword(userPassword);
            contextSource.setReferral("follow");

//            // Инициализируем окружение для serverId
//            Map<String, Object> env = environmentMap.computeIfAbsent(serverId, k -> new HashMap<>());

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

            try {
                logger.info("Preparing LdapContextSource for future connections to {}", url);
                contextSource.afterPropertiesSet();
                LdapTemplate ldapTemplate = new LdapTemplate(contextSource);
                templates.put(serverId, ldapTemplate);
                logger.info("LdapContextSource prepared successfully for future connections to {}", url);
            } catch (Exception e) {
                logger.error("Failed to initialize LdapContextSource for server {}: url={}", serverId, url, e);
            }
        }
        return templates;
    }
}
