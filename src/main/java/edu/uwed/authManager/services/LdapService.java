package edu.uwed.authManager.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.stereotype.Service;

import javax.naming.directory.DirContext;
import java.util.Map;

@Service
public class LdapService {
    private final Map<String, BaseLdapPathContextSource> contextSources;

    @Autowired
    public LdapService(Map<String, BaseLdapPathContextSource> contextSources) {
        this.contextSources = contextSources;
    }

    public boolean testConnection(String serverId) {
        BaseLdapPathContextSource contextSource = contextSources.get(serverId);
        if (contextSource == null) {
            System.err.println("No context source found for server: " + serverId);
            return false;
        }

        // Приводим к LdapContextSource, так как мы знаем, что это правильный тип
        if (!(contextSource instanceof LdapContextSource ldapContextSource)) {
            System.err.println("Context source for server " + serverId + " is not an LdapContextSource");
            return false;
        }

        DirContext ctx = null;
        try {
            ctx = ldapContextSource.getContext( // connects to LDAP server
                ldapContextSource.getUserDn(),
                ldapContextSource.getPassword()
            );
            System.out.println("Successfully connected to LDAP server: " + serverId);
            return true;
        } catch (Exception e) {
            System.err.println("Failed to connect to LDAP server " + serverId + ": " + e.getMessage());
            return false;
        } finally {
            if (ctx != null) {
                try {
                    ctx.close();
                } catch (Exception e) {
                    System.err.println("Failed to close LDAP context for server " + serverId + ": " + e.getMessage());
                }
            }
        }
    }

    public Object searchUser(String serverId, String username) {
        BaseLdapPathContextSource contextSource = contextSources.get(serverId);
        if (contextSource == null) {
            throw new IllegalArgumentException("No context source found for server: " + serverId);
        }

        LdapTemplate ldapTemplate = new LdapTemplate(contextSource);
        return ldapTemplate.lookup("cn=" + username + ",cn=users,dc=uwed,dc=edu");
    }

}
