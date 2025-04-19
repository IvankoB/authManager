package edu.uwed.authManager.configuration;

import com.unboundid.ldap.sdk.LDAPConnection;
import edu.uwed.authManager.ldap.LDAPConnectionPoolFactory;
import edu.uwed.authManager.ldap.LdapProxyServer;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.unboundid.ldap.sdk.LDAPConnectionPool;

import javax.net.ssl.*;
import java.security.KeyStore;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Configuration
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

    @Bean(name = "proxyLdapSslContext") // Переименовали
    public SslContext proxyLdapSslContext() throws Exception {
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

    @Bean(name = "proxyLdapTlsContext")
    public SSLContext proxyLdapTlsContext() throws Exception {
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

    @Bean(name = "targetLdapSecureSocketFactory")
    public SSLSocketFactory targetLdapSecureSocketFactory() throws Exception {
        ConfigProperties.TargetConfig targetConfig = configProperties.getTargetConfig();
        String bundleName = configProperties.getTargetConfig().getSslBundle();
        if (bundleName != null && sslBundles.getBundleNames().contains(bundleName)) {
            SslBundle sslBundle = sslBundles.getBundle(bundleName);
            SSLContext sslContext = SSLContext.getInstance("TLS"); // most common
            sslContext.init(
                sslBundle.getManagers().getKeyManagers(),
                sslBundle.getManagers().getTrustManagers(),
                new java.security.SecureRandom()
            );
            return sslContext.getSocketFactory();
        }
        return null;
    }

    @Bean(name = "targetLdapConnectionPoolFactory")
    public LDAPConnectionPoolFactory targetLdapConnectionPoolFactory(
        @Qualifier("targetLdapSecureSocketFactory") SSLSocketFactory socketFactory
    ) {
        return new LDAPConnectionPoolFactory(configProperties, socketFactory);
    }

}
