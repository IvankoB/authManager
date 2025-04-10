package edu.uwed.authManager.ldap;

import com.unboundid.ldap.protocol.LDAPMessage;
import edu.uwed.authManager.configuration.ConfigProperties;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

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

    private final ConfigProperties configProperties;

    public TargetServerInfo(
        String target,
        LDAPMessage ldapMessage,
        int messageType,
        int messageId,
        ConfigProperties configProperties
    ) {
        this.target = target;
        this.ldapMessage = ldapMessage;
        this.messageType = messageType;
        this.messageId = messageId;
        this.configProperties = configProperties;

        if (target != null) {
            ConfigProperties.LdapServerConfig config = configProperties.getLdapServerConfigs().get(target);
            if (config != null) {
                ConfigProperties.HostPortTuple hostPort = ConfigProperties.HostPortTuple.extractHostAndPort(config.getUrl());
                this.host = hostPort.getHost();
                this.port = hostPort.getPort();
                this.useSsl = config.isLdaps();
                this.startTls = config.isStartTls();
            }
        }
    }
}
