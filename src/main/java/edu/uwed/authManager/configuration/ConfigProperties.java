package edu.uwed.authManager.configuration;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Configuration
@ConfigurationProperties(prefix = "local")
@Data
public class ConfigProperties {

    private Map<String, LdapServerConfig> ldapServers = new HashMap<>();
    private List<ProxyUser> proxyUsers;
    private LdapProxyConfig ldapProxy;

    @Data
    public static class LdapServerConfig {
        private String url;
        private String base;
        private String virtualDn;
        private String userDn;
        private String password;
        private boolean startTls;
        private boolean startTlsRequired;
        private boolean ignoreSslVerification;
        private String referralHandling;
    }

    @Data
    public static class LdapProxyConfig {
        private int portLdap;
        private int portLdaps;
        private long maxMessageSize;
    }

    @Data
    public static class ProxyUser {
        private String dn;
        private String password;
        private List<String> allowedDns;
    }

}
