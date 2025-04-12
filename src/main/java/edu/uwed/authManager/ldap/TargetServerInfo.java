package edu.uwed.authManager.ldap;

import com.unboundid.ldap.protocol.LDAPMessage;
import edu.uwed.authManager.configuration.ConfigProperties;
import lombok.Data;

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

    private final ConfigProperties configProperties;

    public TargetServerInfo(
            String target,
            LDAPMessage ldapMessage,
            int messageType,
            int messageId,
            ConfigProperties configProperties,
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
}

