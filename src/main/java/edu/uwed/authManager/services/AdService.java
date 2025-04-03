package edu.uwed.authManager.services;

/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

import java.util.List;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.stereotype.Service;

//@Service
public class AdService {
    private final LdapTemplate ldapTemplate;

    @Autowired
    public AdService(LdapTemplate ldapTemplate) {
        this.ldapTemplate = ldapTemplate;
    }

    public List<String> search(String base, String filter) {
        return ldapTemplate.search(
            base, 
            filter, 
            (AttributesMapper)attrs -> attrs.get("cn").get().toString()
        );
    }
}    
