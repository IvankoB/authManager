package edu.uwed.authManager.configuration;

import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;
import javax.net.ssl.TrustManagerFactory;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

@Configuration
public class LdapConfig {

    private final Map<String, ConfigProperties.LdapServerConfig> ldapServerConfigs;
    private final SslBundles sslBundles;

    public LdapConfig(
            ConfigProperties configProperties,
            SslBundles sslBundles
    ) {
        this.ldapServerConfigs = configProperties.getLdapServerConfigs();
        this.sslBundles = sslBundles;
    }

    @Bean
    public Map<String, LdapTemplate> ldapTemplates() throws Exception {
        Map<String, LdapTemplate> templates = new HashMap<>();
        for (Map.Entry<String, ConfigProperties.LdapServerConfig> entry : ldapServerConfigs.entrySet()) {
            String serverName = entry.getKey();
            ConfigProperties.LdapServerConfig config = entry.getValue();

            LdapContextSource contextSource = new LdapContextSource();
            contextSource.setUrl(config.getUrl());
            contextSource.setBase(config.getBase());
            contextSource.setUserDn(config.getUserDn());
            contextSource.setPassword(config.getPassword());
            contextSource.afterPropertiesSet();

            templates.put(serverName, new LdapTemplate(contextSource));
        }
        return templates;
    }

    @Bean
    @Qualifier("dc01LdapProxySslContext")
    public SslContext dc01LdapProxySslContext() throws Exception {
        System.out.println("LdapConfig: Creating dc01LdapProxySslContext");
        SslBundle bundle = sslBundles.getBundle("dc01LdapProxy");
        KeyStore keyStore = bundle.getStores().getKeyStore();
        String alias = keyStore.aliases().nextElement();
        if (alias == null) throw new IllegalStateException("No aliases found in KeyStore");
        X509Certificate[] certs = (X509Certificate[]) keyStore.getCertificateChain(alias);
        PrivateKey key = (PrivateKey) keyStore.getKey(alias, null);
        if (certs == null || key == null) throw new IllegalStateException("Cert or key is null");
        KeyStore trustStore = bundle.getStores().getTrustStore();
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        SslContext sslContext = SslContextBuilder.forServer(key, certs)
                .trustManager(tmf)
                .clientAuth(ClientAuth.REQUIRE)
                .build();
        System.out.println("LdapConfig: dc01LdapProxySslContext created=" + sslContext);
        return sslContext;
    }
}