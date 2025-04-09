package edu.uwed.authManager.services;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.ldap.core.ContextMapper;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.stereotype.Service;

import javax.naming.directory.DirContext;
import java.util.List;
import java.util.Map;

@Service
public class LdapService {

    private static final Logger logger = LoggerFactory.getLogger(LdapService.class);

    private final Map<String, BaseLdapPathContextSource> contextSources;

    @Autowired
    public LdapService(@Qualifier("customLdapContextSources") Map<String, BaseLdapPathContextSource> contextSources) {
        this.contextSources = contextSources;
    }

    public boolean testConnection(String serverId) {
        logger.debug("Testing connection for server: {}", serverId);
        BaseLdapPathContextSource contextSource = contextSources.get(serverId);
        if (contextSource == null) {
            logger.error("No context source found for server: {}", serverId);
            return false;
        }

        if (!(contextSource instanceof LdapContextSource ldapContextSource)) {
            logger.error("Context source for server {} is not an LdapContextSource", serverId);
            return false;
        }

        DirContext ctx = null;
        try {
            ctx = ldapContextSource.getContext(
                    ldapContextSource.getUserDn(),
                    ldapContextSource.getPassword()
            );
            logger.info("Successfully connected to LDAP server: {}", serverId);
            return true;
        } catch (Exception e) {
            logger.error("Failed to connect to LDAP server {}: {}", serverId, e.getMessage(), e);
            return false;
        }
    }

    public DirContextOperations searchUser(String serverId, String username) {
        BaseLdapPathContextSource contextSource = contextSources.get(serverId);
        if (contextSource == null) {
            throw new IllegalArgumentException("No context source found for server: " + serverId);
        }

        LdapTemplate ldapTemplate = new LdapTemplate(contextSource);
        return (DirContextOperations) ldapTemplate.lookup("cn=" + username + ",cn=users,dc=uwed,dc=edu");
    }
}
