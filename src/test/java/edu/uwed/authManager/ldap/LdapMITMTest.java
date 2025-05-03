package edu.uwed.authManager.ldap;

import com.unboundid.ldap.sdk.*;
import edu.uwed.authManager.configuration.ConfigProperties;
import org.junit.Ignore;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Predicate;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.util.AssertionErrors.assertEquals;

import edu.uwed.authManager.ldap.LdapMITM.*;
import edu.uwed.authManager.configuration.ConfigProperties;

@SpringBootTest
public class LdapMITMTest {

    @Autowired
    private ConfigProperties configProperties;

    private LdapMITM ldapMITM;
    private String baseDN = "DC=uwed,DC=edu";
    private SearchResultEntry entry;

    @BeforeEach
    public void setUp() {
        // Настройка тестового LDAP-объекта
        entry = new SearchResultEntry(
                new Entry(
                        "CN=Ivan Ivanovich,OU=IT,DC=uwed,DC=edu",
                        new Attribute("objectClass", "person"),
                        new Attribute("sAMAccountName", "ivano"),
                        new Attribute("postalAddress", "ivano@uwed.ac.uz"),
                        new Attribute("distinguishedName", "CN=Ivan Ivanovich,OU=IT,DC=uwed,DC=edu")
                )
        );

        // Настройка TargetConfig через configProperties
        ConfigProperties.TargetConfig targetConfig = configProperties.getTargetConfig();
        List<ConfigProperties.TargetConfig.LocalDnNarrowing> LocalDnNarrowings = new ArrayList<>();
        ConfigProperties.TargetConfig.LocalDnNarrowing dnFilter = new ConfigProperties.TargetConfig.LocalDnNarrowing();
        dnFilter.setAttribute("dn");
        dnFilter.setAutoBaseDn(true);
        LocalDnNarrowings.add(dnFilter);
        ConfigProperties.TargetConfig.LocalDnNarrowing distinguishedNameFilter = new ConfigProperties.TargetConfig.LocalDnNarrowing();
        distinguishedNameFilter.setAttribute("distinguishedName");
        distinguishedNameFilter.setAutoBaseDn(true);
        LocalDnNarrowings.add(distinguishedNameFilter);
        List<ConfigProperties.TargetConfig.LocalAttribute> localAttributes = new ArrayList<>();
        ConfigProperties.TargetConfig.LocalAttribute postalAddressAttr = new ConfigProperties.TargetConfig.LocalAttribute();
        postalAddressAttr.setName("postalAddress");
        postalAddressAttr.setSearchExpression("{{sAMAccountName}}");
        postalAddressAttr.setResultExpression("{{sAMAccountName}}@uwed.ac.uz");
        localAttributes.add(postalAddressAttr);
        targetConfig.setLocalDnNarrowings(LocalDnNarrowings);
        targetConfig.setLocalAttributes(localAttributes);
        targetConfig.setDefaultBase(baseDN);

        // Инициализация ldapMITM
        ldapMITM = new LdapMITM(configProperties);
    }

    @Test
    public void testObjectClassPerson() {
        Filter filter = Filter.createEqualityFilter("objectClass", "person");
        LdapMITM.FilterResult result = ldapMITM.generateLdapFilter(filter, baseDN);
        LdapMITM.FilterExtractionResult extractionResult = new LdapMITM.FilterExtractionResult(
                result.getLocalDnFilterConditions(),
                result.getFilter(),
                result.getLocalDnFilterConditions().stream().anyMatch(LdapMITM.LocalDnFilterCondition::isInvalid)
        );
        Predicate<SearchResultEntry> predicate = ldapMITM.getFilter(extractionResult);

        assertTrue(predicate.test(entry), "Entry should match (objectClass=person)");
        assertEquals("Filter should remain unchanged","(objectClass=person)", result.getFilter().toString());
    }

    @Test
    public void testOrDnOuITOrOuStaff() {
        Filter filter = Filter.createANDFilter(
                Filter.createEqualityFilter("objectClass", "person"),
                Filter.createORFilter(
                        Filter.createEqualityFilter("dn", "ou=IT"),
                        Filter.createEqualityFilter("dn", "ou=Staff")
                )
        );
        LdapMITM.FilterResult result = ldapMITM.generateLdapFilter(filter, baseDN);
        LdapMITM.FilterExtractionResult extractionResult = new LdapMITM.FilterExtractionResult(
                result.getLocalDnFilterConditions(),
                result.getFilter(),
                result.getLocalDnFilterConditions().stream().anyMatch(LdapMITM.LocalDnFilterCondition::isInvalid)
        );
        Predicate<SearchResultEntry> predicate = ldapMITM.getFilter(extractionResult);

        assertTrue(predicate.test(entry), "Entry should match (|(dn=ou=IT)(dn=ou=Staff))");
        assertEquals("Filter should exclude DN conditions", "(&(objectClass=person)(objectClass=*))", result.getFilter().toString());
    }

    @Test
    public void testDnOuIT() {
        Filter filter = Filter.createANDFilter(
                Filter.createEqualityFilter("objectClass", "person"),
                Filter.createEqualityFilter("dn", "ou=IT")
        );
        LdapMITM.FilterResult result = ldapMITM.generateLdapFilter(filter, baseDN);
        LdapMITM.FilterExtractionResult extractionResult = new LdapMITM.FilterExtractionResult(
                result.getLocalDnFilterConditions(),
                result.getFilter(),
                result.getLocalDnFilterConditions().stream().anyMatch(LdapMITM.LocalDnFilterCondition::isInvalid)
        );
        Predicate<SearchResultEntry> predicate = ldapMITM.getFilter(extractionResult);

        assertTrue(predicate.test(entry), "Entry should match (dn=ou=IT)");
        assertEquals("Filter should exclude DN condition", "(&(objectClass=person)(objectClass=*))", result.getFilter().toString());
    }

    @Ignore("Test depends on real server data (specific OUs), excluding for now")
// @Disabled("Test depends on real server data (specific OUs), excluding for now") // Для JUnit 5
    public void testPostalAddressWithOrDnOuITtOrOuITz() {
        Filter filter = Filter.createANDFilter(
                Filter.createEqualityFilter("postalAddress", "ivano@uwed.ac.uz"),
                Filter.createEqualityFilter("objectClass", "person"),
                Filter.createORFilter(
                        Filter.createEqualityFilter("dn", "ou=ITt"),
                        Filter.createEqualityFilter("dn", "ou=ITz")
                )
        );
        LdapMITM.FilterResult result = ldapMITM.generateLdapFilter(filter, baseDN);
        LdapMITM.FilterExtractionResult extractionResult = new LdapMITM.FilterExtractionResult(
                result.getLocalDnFilterConditions(),
                result.getFilter(),
                result.getLocalDnFilterConditions().stream().anyMatch(LdapMITM.LocalDnFilterCondition::isInvalid)
        );
        Predicate<SearchResultEntry> predicate = ldapMITM.getFilter(extractionResult);

        assertFalse(predicate.test(entry), "Entry should NOT match (|(dn=ou=ITt)(dn=ou=ITz))");
        assertTrue(result.getFilter().toString().contains("sAMAccountName=ivano"), "Filter should transform postalAddress");
    }

    @Test
    public void testPostalAddressWithDnOuITt() {
        Filter filter = Filter.createANDFilter(
                Filter.createEqualityFilter("postalAddress", "ivano@uwed.ac.uz"),
                Filter.createEqualityFilter("objectClass", "person"),
                Filter.createEqualityFilter("dn", "ou=ITt")
        );
        LdapMITM.FilterResult result = ldapMITM.generateLdapFilter(filter, baseDN);
        LdapMITM.FilterExtractionResult extractionResult = new LdapMITM.FilterExtractionResult(
                result.getLocalDnFilterConditions(),
                result.getFilter(),
                result.getLocalDnFilterConditions().stream().anyMatch(LdapMITM.LocalDnFilterCondition::isInvalid)
        );
        Predicate<SearchResultEntry> predicate = ldapMITM.getFilter(extractionResult);

        assertFalse(predicate.test(entry), "Entry should NOT match (dn=ou=ITt)");
        assertTrue(result.getFilter().toString().contains("sAMAccountName=ivano"), "Filter should transform postalAddress");
    }

    @Test
    public void testPostalAddressWithDnOuIT() {
        Filter filter = Filter.createANDFilter(
                Filter.createEqualityFilter("postalAddress", "ivano@uwed.ac.uz"),
                Filter.createEqualityFilter("objectClass", "person"),
                Filter.createEqualityFilter("dn", "ou=IT")
        );
        LdapMITM.FilterResult result = ldapMITM.generateLdapFilter(filter, baseDN);
        LdapMITM.FilterExtractionResult extractionResult = new LdapMITM.FilterExtractionResult(
                result.getLocalDnFilterConditions(),
                result.getFilter(),
                result.getLocalDnFilterConditions().stream().anyMatch(LdapMITM.LocalDnFilterCondition::isInvalid)
        );
        Predicate<SearchResultEntry> predicate = ldapMITM.getFilter(extractionResult);

        assertTrue(predicate.test(entry), "Entry should match (dn=ou=IT)");
        assertTrue(result.getFilter().toString().contains("sAMAccountName=ivano"), "Filter should transform postalAddress");
    }

    @Test
    public void testPostalAddressWithDnOuZZZIT() {
        Filter filter = Filter.createANDFilter(
                Filter.createEqualityFilter("postalAddress", "ivano@uwed.ac.uz"),
                Filter.createEqualityFilter("objectClass", "person"),
                Filter.createEqualityFilter("dn", "ouZZZ=IT")
        );
        LdapMITM.FilterResult result = ldapMITM.generateLdapFilter(filter, baseDN);
        LdapMITM.FilterExtractionResult extractionResult = new LdapMITM.FilterExtractionResult(
                result.getLocalDnFilterConditions(),
                result.getFilter(),
                result.getLocalDnFilterConditions().stream().anyMatch(LdapMITM.LocalDnFilterCondition::isInvalid)
        );
        Predicate<SearchResultEntry> predicate = ldapMITM.getFilter(extractionResult);

        assertFalse(predicate.test(entry), "Entry should NOT match (dn=ouZZZ=IT)");

        // Добавим отладочный лог
        String filterString = result.getFilter().toString();
        System.out.println("Filter toString before assert: " + filterString);

        assertEquals("Filter should be non-matching", "(objectClass=nonexistent)", filterString);
    }

     @Test
    public void testPostalAddressWithOrDistinguishedNameOuIT() {
        Filter filter = Filter.createANDFilter(
                Filter.createEqualityFilter("postalAddress", "ivano@uwed.ac.uz"),
                Filter.createEqualityFilter("objectClass", "person"),
                Filter.createORFilter(
                        Filter.createEqualityFilter("distinguishedName", "ou=IT")
                )
        );
        LdapMITM.FilterResult result = ldapMITM.generateLdapFilter(filter, baseDN);
        LdapMITM.FilterExtractionResult extractionResult = new LdapMITM.FilterExtractionResult(
                result.getLocalDnFilterConditions(),
                result.getFilter(),
                result.getLocalDnFilterConditions().stream().anyMatch(LdapMITM.LocalDnFilterCondition::isInvalid)
        );
        Predicate<SearchResultEntry> predicate = ldapMITM.getFilter(extractionResult);

        assertTrue(predicate.test(entry), "Entry should match (|(distinguishedName=ou=IT))");
        assertTrue(result.getFilter().toString().contains("sAMAccountName=ivano"), "Filter should transform postalAddress");
    }

    @Test
    public void testPostalAddressWithOrDistinguishedNameOuITOrDnOuITz() {
        Filter filter = Filter.createANDFilter(
                Filter.createEqualityFilter("postalAddress", "ivano@uwed.ac.uz"),
                Filter.createEqualityFilter("objectClass", "person"),
                Filter.createORFilter(
                        Filter.createEqualityFilter("distinguishedName", "ou=IT"),
                        Filter.createEqualityFilter("dn", "ou=ITz")
                )
        );
        FilterResult result = ldapMITM.generateLdapFilter(filter, baseDN);
        FilterExtractionResult extractionResult = new FilterExtractionResult(
                result.getLocalDnFilterConditions(),
                result.getFilter(),
                result.getLocalDnFilterConditions().stream().anyMatch(LdapMITM.LocalDnFilterCondition::isInvalid)
        );
        Predicate<SearchResultEntry> predicate = ldapMITM.getFilter(extractionResult);

        assertTrue(predicate.test(entry), "Entry should match (|(distinguishedName=ou=IT)(dn=ou=ITz))");
        assertTrue(result.getFilter().toString().contains("sAMAccountName=ivano"), "Filter should transform postalAddress");
    }

    @Test
    public void testNoLocalFiltersConfigured() {
        ConfigProperties customConfig = new ConfigProperties();
        ConfigProperties.TargetConfig targetConfig = new ConfigProperties.TargetConfig();
        targetConfig.setLocalDnNarrowings(Collections.emptyList());
        targetConfig.setLocalAttributes(Collections.emptyList());
        LdapMITM ldapMITMWithNoFilters = new LdapMITM(customConfig);

        Filter filter = Filter.createEqualityFilter("objectClass", "person");
        FilterResult result = ldapMITMWithNoFilters.generateLdapFilter(filter, baseDN);
        FilterExtractionResult extractionResult = new FilterExtractionResult(
                result.getLocalDnFilterConditions(),
                result.getFilter(),
                result.getLocalDnFilterConditions().stream().anyMatch(LdapMITM.LocalDnFilterCondition::isInvalid)
        );
        Predicate<SearchResultEntry> predicate = ldapMITMWithNoFilters.getFilter(extractionResult);

        assertTrue(predicate.test(entry), "Entry should pass when no local filters are configured");
        assertEquals("Filter should remain unchanged", "(objectClass=person)", result.getFilter().toString());
    }
}