package edu.uwed.authManager.configuration;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Configuration
public class ConfigProperties {

    @Bean
    @ConfigurationProperties(prefix = "local.ldap.servers")
    public Map<String, LdapServerConfig> getLdapServerConfigs() {
        return new HashMap<>();
    }

    @Bean
    @ConfigurationProperties(prefix = "local.ldap.proxy.users")
    public List<ProxyUser> getProxyUsers() {
        return new ArrayList<>();
    }

    @Bean
    @ConfigurationProperties(prefix = "local.ldap.proxy")
    public ProxyConfig getProxyConfig() {
        return new ProxyConfig();
    }

    @Data
    public static class LdapServerConfig {
        private String url;
        private String base;
        private String userDn;
        private String password;
        private String virtualDn;
    }

    @Data
    public static class ProxyUser {
        private String dn;
        private String password;
        private List<String> allowedDns;
    }

    @Data
    public static class ProxyConfig {
        private int maxMessageSize;
        private Port port;

        @Data
        public static class Port {
            private int ldap;
            private int ldaps;
        }

    }
}
