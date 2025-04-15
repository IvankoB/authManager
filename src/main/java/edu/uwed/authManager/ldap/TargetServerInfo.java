package edu.uwed.authManager.ldap;

import com.unboundid.ldap.protocol.LDAPMessage;
import edu.uwed.authManager.configuration.ConfigProperties;
import lombok.Data;
import org.apache.logging.log4j.util.Strings;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Data
public class TargetServerInfo {
    private String target;
    private LDAPMessage ldapMessage;
    private int messageType;
    private int messageId;
    private String host;
    private int port;
    private boolean useSsl;
    private boolean startTls;
    private LdapConstants.LDAP_PROTOCOL proto;
    private String url;

    private String _host;
    private String _scheme;
    private int _port;
    private boolean _secure;

    private final ConfigProperties configProperties;

    public TargetServerInfo(
            String target,
            ConfigProperties configProperties,
            LDAPMessage ldapMessage,
            int messageType,
            int messageId,
            LdapConstants.LDAP_PROTOCOL proto
    ) {
        this.target = target;
        this.ldapMessage = ldapMessage;
        this.messageType = messageType;
        this.messageId = messageId;
        this.configProperties = configProperties;
        this.proto = proto;

        if (target != null) {
            ConfigProperties.LdapServerConfig config = configProperties.getLdapServerConfigs().get(target);
            if (config != null) {
                ConfigProperties.HostPortTuple hostPort = ConfigProperties.HostPortTuple.extractHostAndPort(config.getUrl());
                this.host = hostPort.getHost();
                this.port = hostPort.getPort();
                this.useSsl = config.isLdaps();
                this.startTls = config.isStartTls();
                this.proto = LdapConstants.LDAP_PROTOCOL.LDAP;
                if (useSsl) {
                    this.proto = LdapConstants.LDAP_PROTOCOL.LDAPS;
                } else if (startTls) {
                    this.proto = LdapConstants.LDAP_PROTOCOL.LDAP_TLS;
                }
            }
        }
    }

    public TargetServerInfo(
            String target,
            ConfigProperties configProperties
    ) {
        this.target = target;
        this.configProperties = configProperties;
        if (target != null) {
            ConfigProperties.LdapServerConfig config = configProperties.getLdapServerConfigs().get(target);
            if (config != null) {
                ConfigProperties.HostPortTuple hostPort = ConfigProperties.HostPortTuple.extractHostAndPort(config.getUrl());
                String security  = config.getSecurity();
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
                if (Stream.of("ssl","ldaps").map(String::toLowerCase).toList().contains(security.toLowerCase())) {
                    this.url = "ldaps://" + config.getHost() + ":" + ldapsPort;
                    this._secure = true;
                } else
                if (Stream.of("tls","starttls").map(String::toLowerCase).toList().contains(security.toLowerCase())) {
                    this.url = "ldap://" + config.getHost() + ":" + ldapPort;
                    this._secure = true;
                } else {
                    this.url = "ldap://" + config.getHost() + ":" + ldapPort;
                    this._secure = false;
                }
            }
            URI uri;
            try {
                uri = new URI(this.url);
                this._host = uri.getHost();
                this._port = uri.getPort();
                this._scheme = uri.getScheme();
            } catch (URISyntaxException e) {
                throw new RuntimeException("Unable to parse this URL: " + this.url + " because of: " + e);
            }
        }

    }
    public String getHost() {
        return this._host;
    }
    public int getPort() {
        return this._port;
    }
    public String getScheme() {
        return this._scheme;
    }
    public  LdapConstants.LDAP_PROTOCOL getProto() {
        if (isStartTls()) return LdapConstants.LDAP_PROTOCOL.LDAP_TLS;
        if (isLdaps()) return LdapConstants.LDAP_PROTOCOL.LDAPS;
        return LdapConstants.LDAP_PROTOCOL.LDAP;
    }
    public  boolean isSecure() {
        return this._secure;
    }
    public boolean isStartTls() {
        return this._secure && this._scheme.equals("ldap");
    }
    public boolean isLdaps() {
        return this._secure && this._scheme.equals("ldaps");
    }

}
