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
import java.util.*;
import java.util.stream.Collectors;

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

    @Bean(name = "inboundLdapSslContext") // Переименовали
    public SslContext inboundLdapSslContext() throws Exception {
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

    @Bean(name = "inboundLdapTlsContext")
    public SSLContext inboundLdapTlsContext() throws Exception {
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

    @Bean(name = "outboundLdapSslContexts")
    public Map<String, SslContext> outboundLdapSslContexts() throws Exception {
        Map<String, SslContext> sslContexts = new HashMap<>();
        SslContext defaultLdapsContext = inboundLdapSslContext(); // Фоллбэк из @Bean(name = "inboundLdapSslContext")
        sslContexts.put("ldaps", defaultLdapsContext);
        logger.debug("Added fallback 'ldaps' to proxySslContexts");

        for (Map.Entry<String, ConfigProperties.LdapServerConfig> entry : configProperties.getLdapServerConfigs().entrySet()) {
            String serverName = entry.getKey(); // "dc-01"
            ConfigProperties.LdapServerConfig config = entry.getValue();
            String bundleName = config.getSslBundle(); // "dc-01" или "ldaps"

            if (bundleName != null && !bundleName.equals("ldaps") && sslBundles.getBundleNames().contains(bundleName)) {
                SslBundle sslBundle = sslBundles.getBundle(bundleName);
                KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                kmf.init(sslBundle.getStores().getKeyStore(), sslBundle.getKey().getPassword() != null ? sslBundle.getKey().getPassword().toCharArray() : null);
                TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(sslBundle.getStores().getTrustStore());

                SslContextBuilder builder = SslContextBuilder.forClient().keyManager(kmf).trustManager(tmf);

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

    @Bean(name = "outboundLdapTlsContexts")
    public Map<String, SSLContext> outboundLdapTlsContexts() throws Exception {
        Map<String, SSLContext> sslContexts = new HashMap<>();
        for (Map.Entry<String, ConfigProperties.LdapServerConfig> entry : configProperties.getLdapServerConfigs().entrySet()) {
            String serverName = entry.getKey();
            ConfigProperties.LdapServerConfig config = entry.getValue();
            String bundleName = config.getSslBundle();

            if (bundleName != null && sslBundles.getBundleNames().contains(bundleName)) {
                SslBundle sslBundle = sslBundles.getBundle(bundleName);
                SSLContext sslContext = SSLContext.getInstance("TLS"); // most common
                sslContext.init(
                        sslBundle.getManagers().getKeyManagers(),
                        sslBundle.getManagers().getTrustManagers(),
                        new java.security.SecureRandom()
                );

                sslContexts.put(serverName, sslContext);
                logger.debug("Created outgoing SSLContext for server: {}", serverName);
            }
        }
        logger.info("outgoingSslContexts initialized with keys: {}", sslContexts.keySet());
        return sslContexts;
    }

    @Bean(name = "outboundSslSocketFactories")
    public Map<String, SSLSocketFactory> outboundSslSocketFactories() throws Exception {
        Map<String, SSLSocketFactory> factories = new HashMap<>();
        for (Map.Entry<String, ConfigProperties.LdapServerConfig> entry : configProperties.getLdapServerConfigs().entrySet()) {
            String serverName = entry.getKey();
            ConfigProperties.LdapServerConfig config = entry.getValue();
            String bundleName = config.getSslBundle();

            if (bundleName != null && sslBundles.getBundleNames().contains(bundleName)) {
                SslBundle sslBundle = sslBundles.getBundle(bundleName);
                SSLContext sslContext = SSLContext.getInstance("TLS"); // most common
                sslContext.init(
                        sslBundle.getManagers().getKeyManagers(),
                        sslBundle.getManagers().getTrustManagers(),
                        new java.security.SecureRandom()
                );

                factories.put(serverName, sslContext.getSocketFactory());
                logger.debug("Created outgoing SSLSocketFactory for server: {}", serverName);
            }
        }
        logger.info("SSLSocketFactory initialized with keys: {}", factories.keySet());
        return factories;
    }

    @Bean(name = "outboundLdapTemplates")
    public Map<String, LdapTemplate> outboundLdapTemplates() throws Exception {
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
///// no settins anymore                env.put("java.naming.ldap.starttls.required", String.valueOf(config.isStartTlsRequired()));
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

            if (!config.isIgnoreSslVerification() && config.getSslBundle() != null) {
                SslBundle sslBundle = sslBundles.getBundle(config.getSslBundle());
                SSLContext sslContext = sslBundle.createSslContext();
            }

            contextSource.setBaseEnvironmentProperties(env);
            System.out.println("LdapConfig: Attempting to initialize context for " + config.getUrl());
            contextSource.afterPropertiesSet();
            System.out.println("LdapConfig: Context initialized successfully for " + config.getUrl());

            templates.put(serverName, new LdapTemplate(contextSource));
        }
        return templates;
    }

    private static SSLSocketFactory getSslSocketFactory(SSLContext customContext, SSLParameters sslParams) {
        SSLSocketFactory baseFactory = customContext.getSocketFactory();
        return new SSLSocketFactory() {
            @Override
            public Socket createSocket() throws IOException {
                SSLSocket socket = (SSLSocket) baseFactory.createSocket();
                socket.setSSLParameters(sslParams);
                return socket;
            }

            @Override
            public Socket createSocket(String host, int port) throws IOException {
                SSLSocket socket = (SSLSocket) baseFactory.createSocket(host, port);
                socket.setSSLParameters(sslParams);
                return socket;
            }

            @Override
            public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
                SSLSocket socket = (SSLSocket) baseFactory.createSocket(host, port, localHost, localPort);
                socket.setSSLParameters(sslParams);
                return socket;
            }

            @Override
            public Socket createSocket(InetAddress host, int port) throws IOException {
                SSLSocket socket = (SSLSocket) baseFactory.createSocket(host, port);
                socket.setSSLParameters(sslParams);
                return socket;
            }

            @Override
            public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
                SSLSocket socket = (SSLSocket) baseFactory.createSocket(address, port, localAddress, localPort);
                socket.setSSLParameters(sslParams);
                return socket;
            }

            @Override
            public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
                SSLSocket socket = (SSLSocket) baseFactory.createSocket(s, host, port, autoClose);
                socket.setSSLParameters(sslParams);
                return socket;
            }

            @Override
            public String[] getDefaultCipherSuites() {
                return baseFactory.getDefaultCipherSuites();
            }

            @Override
            public String[] getSupportedCipherSuites() {
                return baseFactory.getSupportedCipherSuites();
            }
        };
    }

    @Bean(name = "dc-01")
    public ConfigProperties.LdapServerConfig dc01ServerConfig() {
        return configProperties.getLdapServerConfigs().get("dc-01");
    }
}
