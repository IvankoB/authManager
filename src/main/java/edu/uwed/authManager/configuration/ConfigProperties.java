package edu.uwed.authManager.configuration;

import com.unboundid.ldap.sdk.DereferencePolicy;
import edu.uwed.authManager.ldap.LdapConstants;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.net.URI;
import java.net.URISyntaxException;
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
    @ConfigurationProperties(prefix = "local.ldap.proxy.users")
    public List<ProxyUser> getProxyUsers() {
        return new ArrayList<>();
    }

    @Bean
    @ConfigurationProperties(prefix = "local.ldap.proxy")
    public ProxyConfig getProxyConfig() {
        return new ProxyConfig();
    }

    @Bean
    @ConfigurationProperties(prefix = "local.ldap.target")
    public TargetConfig getTargetConfig() {
        return new TargetConfig();
    }

    @Data
    public static class TargetConfig {
            private String host; // Заменено с name
            private int ldapPort = 389;
            private int ldapsPort = 636;
            private String security = "none"; // none | (tls | startTLS) | (ldaps / ssl)
            private String userDn;
            private String password;
            private boolean ignoreSslVerification = false;
            ///private String referralHandling = "follow"; // follow | ignore | throw
            private String sslBundle;
            private String sslProtocols;
            private String sslCiphers;
            private List<LocalAttribute> localAttributes = new ArrayList<>();
            private List<LocalDnFilter> localDnFilters = new ArrayList<>();
            private String domain; // local.ldap.target.domain
            private List<String> localDomains = new ArrayList<>(); // local.ldap.target.local-domains
            private boolean mapLocalDomains = true; // redirect <username>@local-domains[*] BINDs to <username>@domain
            private int clientTimeoutSec = 5; //
            private long operationTimeoutMs = 5000; // Таймаут для синхронных операций (BIND, SEARCH)
            private long searchAsyncTimeoutSec = 5; // Таймаут для асинхронного SEARCH
            private int poolMaxConnections = 50; // Максимум соединений в пуле
            private int threadPoolSize = 50; // Размер пула потоков для синхронных операций
            private long disconnectDelayMs = 500; // Задержка перед закрытием соединения
            private DereferencePolicy referralPolicy = DereferencePolicy.NEVER; // NEVER | SEARCHING | FINDING | ALWAYS
            private int maxRecords = 10000;
            private String defaultBase;

            @Data
            public static class LocalAttribute {
                private String name;
                private String searchExpression;
                private String resultExpression;
                private boolean localDomainsOnly; // Обновлённое название флага
            }

            @Data
            public static class LocalDnFilter {
                private String attribute; // Например, "dn" или "distinguishedName"
                //private LdapConstants.FILTER_TYPE type;      // "dn" или "regular"
                private boolean autoBaseDn; // Автоматически добавлять baseDN
                private String baseDn;    // Конкретный baseDN для фильтра (пока не используется)

//                public void setType (String type) {
//                    if (type == null || type.trim().isEmpty()) {
//                        this.type = LdapConstants.FILTER_TYPE.REGULAR;
//                        return;
//                    }
//                    switch (type.trim().toUpperCase()) {
//                        case "REGULAR":
//                            this.type = LdapConstants.FILTER_TYPE.REGULAR;
//                            break;
//                        case "DN":
//                            this.type = LdapConstants.FILTER_TYPE.DN;
//                            break;
//                        default:
//                            throw new IllegalArgumentException(
//                                    String.format("Invalid local filter type value '%s'. Expected one of: REGULAR, DN", type)
//                            );
//                    }
//                }
            }

            public String getUrl() {
                String protocol = "ldap";
                int port = ldapPort;
                if ("ldaps".equalsIgnoreCase(security)) {
                    protocol = "ldaps";
                    port = ldapsPort;
                }
                return String.format("%s://%s:%d", protocol, host, port);
            }

            public boolean isStartTls() {
                return "startTLS".equalsIgnoreCase(security) || "tls".equalsIgnoreCase(security);
            }

            public boolean isLdaps() {
                return "ldaps".equalsIgnoreCase(security)  || "ssl".equalsIgnoreCase(security);
            }

            public void setReferralPolicy(String policy) {
                if (policy == null || policy.trim().isEmpty()) {
                    this.referralPolicy = DereferencePolicy.NEVER;
                    return;
                }
                switch (policy.trim().toUpperCase()) {
                    case "NEVER":
                        this.referralPolicy = DereferencePolicy.NEVER;
                        break;
                    case "SEARCHING":
                        this.referralPolicy = DereferencePolicy.SEARCHING;
                        break;
                    case "FINDING":
                        this.referralPolicy = DereferencePolicy.FINDING;
                        break;
                    case "ALWAYS":
                        this.referralPolicy = DereferencePolicy.ALWAYS;
                        break;
                    default:
                        throw new IllegalArgumentException(
                            String.format("Invalid DereferencePolicy value '%s'. Expected one of: NEVER, SEARCHING, FINDING, ALWAYS", policy)
                    );
                }
            }
        }

    @Data
    public static class ProxyUser {
        private String dn;
        private String password;
    }

    @Data
    public static class ProxyConfig {
        private int maxMessageSize;
        private Port port;
        private String sslProtocols; // Опционально для входящих соединений

        @Data
        public static class Port {
            private int ldap;
            private int ldaps;
        }

    }

    @Data
    @AllArgsConstructor
    public static class HostPortTuple {
        private String host;
        private int port;

        public static HostPortTuple extractHostAndPort(String url) {
            if (url == null || url.isEmpty()) {
                throw new IllegalArgumentException("URL is null or empty in LdapServerConfig");
            }

            try {
                URI uri = new URI(url);
                String host = uri.getHost();
                int port = uri.getPort();

                // Если порт не указан, используем стандартный в зависимости от схемы
                if (port == -1) {
                    if ("ldaps".equalsIgnoreCase(uri.getScheme())) {
                        port = 636; // Стандартный порт для LDAPS
                    } else {
                        port = 389; // Стандартный порт для LDAP
                    }
                }

                if (host == null || host.isEmpty()) {
                    throw new IllegalArgumentException("Host is null or empty in URL: " + url);
                }

                return new HostPortTuple(host, port);
            } catch (URISyntaxException e) {
                throw new IllegalArgumentException("Invalid URL format in LdapServerConfig: " + url, e);
            }
        }
    }



}