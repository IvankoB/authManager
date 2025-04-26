package edu.uwed.authManager.ldap;

import com.unboundid.ldap.protocol.LDAPMessage;
import edu.uwed.authManager.configuration.ConfigProperties;
import lombok.Data;
import lombok.Getter;
import org.apache.logging.log4j.util.Strings;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Getter
public class TargetServerInfo {

    private final ConfigProperties configProperties;

    private LdapConstants.PROXY_ENDPOINT endpoint;

    private String scheme;
    private String host;
    private int port;

    private String url;
    private boolean secure;

    private LDAPMessage ldapMessage;

    private byte messageType;

    private int messageId;
    private final LdapConstants.BIND_STATUS bindStatus;

    public TargetServerInfo(
            LdapConstants.PROXY_ENDPOINT endpoint,
            ConfigProperties configProperties,
            LDAPMessage ldapMessage,
            byte messageType,
            int messageId,
            LdapConstants.BIND_STATUS bindStatus
    ) {
        this.endpoint = endpoint;
        this.configProperties = configProperties;
        this.ldapMessage = ldapMessage;
        this.messageType = messageType;
        this.messageId = messageId;
        this.bindStatus = bindStatus;

        if (endpoint.equals(LdapConstants.PROXY_ENDPOINT.TARGET)) {
            ConfigProperties.TargetConfig config = configProperties.getTargetConfig();
            String security = config.getSecurity();
            if (Strings.isBlank(security)) {
                security = "none";
            }
            int ldapPort = config.getLdapPort();
            if (ldapPort == 0) {
                ldapPort = 389;
            }
            int ldapsPort = config.getLdapsPort();
            if (ldapsPort == 0) {
                ldapsPort = 636;
            }
            if (Stream.of("ssl", "ldaps").map(String::toLowerCase).toList().contains(security.toLowerCase())) {
                this.url = "ldaps://" + config.getHost() + ":" + ldapsPort;
                this.secure = true;
            } else if (Stream.of("tls", "starttls").map(String::toLowerCase).toList().contains(security.toLowerCase())) {
                this.url = "ldap://" + config.getHost() + ":" + ldapPort;
                this.secure = true;
            } else {
                this.url = "ldap://" + config.getHost() + ":" + ldapPort;
                this.secure = false;
            }
            try {
                URI uri = new URI(this.url);
                this.host = uri.getHost();
                this.port = uri.getPort();
                this.scheme = uri.getScheme();
            } catch (URISyntaxException e) {
                throw new RuntimeException("Unable to parse this URL: " + this.url + " because of: " + e);
            }
        }
    }

    public  LdapConstants.LDAP_PROTOCOL getProto() {
        if (isStartTls()) return LdapConstants.LDAP_PROTOCOL.LDAP_TLS;
        if (isLdaps()) return LdapConstants.LDAP_PROTOCOL.LDAPS;
        return LdapConstants.LDAP_PROTOCOL.LDAP;
    }

    public boolean isStartTls() {
        return this.secure && this.scheme.equals("ldap");
    }

    public boolean isLdaps() {
        return this.secure && this.scheme.equals("ldaps");
    }

}
