package edu.uwed.authManager.configuration;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/*
local.ldap.servers.dc-01.url=ldap://DC-01.uwed.edu:389
local.ldap.servers.dc-01.start-tls=true
local.ldap.servers.dc-01.start-tls-required=true
local.ldap.servers.dc-01.ignore-ssl-verification=false
### Возможные значения:
# follow* — следовать за реферралами (по умолчанию).
# ignore — игнорировать реферралы.
# throw  — бросать исключение при получении реферрала.
local.ldap.servers.dc-01.referral-handling=follow
local.ldap.servers.dc-01.user-dn=cn=vmail,cn=users,dc=uwed,dc=edu
local.ldap.servers.dc-01.password=Vm@vm@vM
local.ldap.servers.dc-01.base=DC=uwed,DC=edu
local.ldap.servers.dc-01.virtual-dn=dc=dc-01,dc=proxy,dc=local

# Настройки прокси-сервера
local.ldap.proxy.port.ldap=389
local.ldap.proxy.port.ldaps=636
local.ldap.proxy.max-message-size=1048576

# Настройки прокси-пользователей
local.proxy-users[0].dn=cn=ldap-proxy,dc=proxy,dc=local
local.proxy-users[0].password=ProxyPass123
local.proxy-users[0].allowed-dns[0]=[*]
local.proxy-users[1].dn=cn=proxy-user2,dc=proxy,dc=local
local.proxy-users[1].password=User2Pass
local.proxy-users[1].allowed-dns[0]=dc=dc-01,dc=proxy,dc=local

* */
@Configuration
@Data
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
        private boolean startTls;
        private boolean startTlsRequired;
        private boolean ignoreSslVerification;
        private String referralHandling;
        private String sslBundle;
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
