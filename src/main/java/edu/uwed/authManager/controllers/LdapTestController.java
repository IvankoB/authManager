package edu.uwed.authManager.controllers;

import edu.uwed.authManager.services.LdapService;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LdapTestController {

    private final LdapService ldapService;

    @Autowired
    public LdapTestController(LdapService ldapService) {
        this.ldapService = ldapService;
    }

    @GetMapping("/test-ldap")
    public String testLdapConnection(
        @RequestParam String serverId
    ) {
        boolean success = ldapService.testConnection(serverId);
        return success ? "LDAP connection successful for " + serverId : "LDAP connection failed for " + serverId;
    }
}
