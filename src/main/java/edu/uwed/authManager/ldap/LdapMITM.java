package edu.uwed.authManager.ldap;

import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.SearchResultEntryProtocolOp;
import com.unboundid.ldap.sdk.*;
import edu.uwed.authManager.configuration.ConfigProperties;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.function.BiFunction;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class LdapMITM {
    private static final Logger logger = LoggerFactory.getLogger(LdapMITM.class);
    private final ConfigProperties configProperties;

    @Data
    public static class LocalDnFilterCondition {
        private final String type;        // "SIMPLE", "OR", "AND", "NOT"
        //private final LdapConstants.FILTER_TYPE filterType = LdapConstants.FILTER_TYPE.DN;  // Используем перечисление из LdapConstants
        private final String attribute;   // Например, "distinguishedName"
        private final List<String> values; // Для SIMPLE — одно значение, для OR — список значений
        private final boolean autoBaseDn; // Нужно ли добавлять baseDN
    }

    // Обновляем FilterResult
    @Data
    @AllArgsConstructor
    public static class FilterResult {
        private final Filter filter;
        private final List<Map.Entry<String, String>> filterValues; // Пары {attributeName, value}
        private final List<LocalDnFilterCondition> localDnFilterConditions;

        public FilterResult(Filter filter, List<Map.Entry<String, String>> filterValues) {
            this.filter = filter;
            this.filterValues = filterValues;
            this.localDnFilterConditions = new ArrayList<>();
        }
    }

    @Autowired
    public LdapMITM(ConfigProperties configProperties) {
        this.configProperties = configProperties;
    }

    // Валидация DN-фильтра
    private boolean isValidDnFilter(String value, boolean autoBaseDn) {
        if (value == null) return false;

        // Разбиваем фильтр на компоненты (cn=Иван,ou=ИТ,dc=uwed)
        String[] components = value.split(",");
        if (components.length == 0) return false;

        boolean hasDc = false;
        for (String component : components) {
            if (!component.contains("=")) return false;
            String[] parts = component.split("=", 2);
            if (parts.length != 2) return false;
            String key = parts[0].trim();
            String val = parts[1].trim();

            // Проверяем, что ключ — это cn, ou, или dc
            if (!key.matches("cn|ou|dc")) {
                return false;
            }

            // Проверяем, что ключ содержит только латинские буквы
            if (!key.matches("[a-zA-Z]+")) {
                return false;
            }

            // Проверяем наличие dc=
            if (key.equals("dc")) {
                hasDc = true;
            }

            // Значение может быть любым, но не пустым
            if (val.isEmpty()) {
                return false;
            }
        }

        // Если autoBaseDn=false, требуем наличие dc=
        if (!autoBaseDn && !hasDc) {
            return false;
        }

        return true;
    }

    // Проверка DN на точное соответствие фильтру

    private boolean checkDnFilter(String dn, String filterValue, boolean autoBaseDn, String baseDN) {
        if (dn == null || filterValue == null || baseDN == null) {
            logger.debug("Invalid input: dn={}, filterValue={}, baseDN={}", dn, filterValue, baseDN);
            return false;
        }

        // Формируем полный фильтр, добавляя baseDN, если autoBaseDn=true
        String fullFilterValue = autoBaseDn ? appendBaseDNIfMissing(filterValue, baseDN) : filterValue;

        // Разбиваем DN и фильтр на компоненты
        String[] filterComponents = fullFilterValue.toLowerCase().split(",");
        String[] dnComponents = dn.toLowerCase().split(",");

        // Проверяем, что DN содержит достаточно компонентов
        if (dnComponents.length < filterComponents.length) {
            logger.debug("DN {} has fewer components ({}) than filter {} ({})", dn, dnComponents.length, fullFilterValue, filterComponents.length);
            return false;
        }

        // Проверяем совпадение компонентов с конца (базового DN)
        int filterIndex = filterComponents.length - 1;
        int dnIndex = dnComponents.length - 1;

        while (filterIndex >= 0 && dnIndex >= 0) {
            String filterComponent = filterComponents[filterIndex];
            String dnComponent = dnComponents[dnIndex];

            if (!filterComponent.contains("=") || !dnComponent.contains("=")) {
                logger.debug("Invalid component format: filterComponent={}, dnComponent={}", filterComponent, dnComponent);
                return false;
            }

            String[] filterParts = filterComponent.split("=", 2);
            String[] dnParts = dnComponent.split("=", 2);
            if (filterParts.length != 2 || dnParts.length != 2) {
                logger.debug("Invalid component structure: filterComponent={}, dnComponent={}", filterComponent, dnComponent);
                return false;
            }

            String filterKey = filterParts[0].trim();
            String filterValuePart = filterParts[1].trim();
            String dnKey = dnParts[0].trim();
            String dnValue = dnParts[1].trim();

            if (!filterKey.equals(dnKey)) {
                logger.debug("Key mismatch: filterKey={} != dnKey={} in components {} and {}", filterKey, dnKey, filterComponent, dnComponent);
                return false;
            }

            if (filterValuePart.contains("*")) {
                String pattern = filterValuePart.replace("*", ".*");
                if (!dnValue.matches(pattern)) {
                    logger.debug("Value mismatch: dnValue={} does not match pattern={} in filter {}", dnValue, pattern, filterComponent);
                    return false;
                }
            } else if (!filterValuePart.equals(dnValue)) {
                logger.debug("Value mismatch: filterValue={} != dnValue={} in components {} and {}", filterValuePart, dnValue, filterComponent, dnComponent);
                return false;
            }

            filterIndex--;
            dnIndex--;
        }

        // Все компоненты фильтра должны быть сопоставлены
        if (filterIndex >= 0) {
            logger.debug("Not all filter components matched: remaining components in filter {}", fullFilterValue);
            return false;
        }

        logger.debug("DN {} matches filter {}", dn, fullFilterValue);
        return true;
    }



    private boolean isInvalidFilter(Filter filter) {
        if (filter.getFilterType() == Filter.FILTER_TYPE_EQUALITY) {
            return "objectClass".equalsIgnoreCase(filter.getAttributeName()) && "invalid".equals(filter.getAssertionValue());
        } else if (filter.getFilterType() == Filter.FILTER_TYPE_AND || filter.getFilterType() == Filter.FILTER_TYPE_OR) {
            for (Filter subFilter : filter.getComponents()) {
                if (isInvalidFilter(subFilter)) {
                    return true;
                }
            }
        }
        return false;
    }


    // Метод для извлечения условий локальной фильтрации
    private Filter extractLocalFilters(Filter filter, List<LocalDnFilterCondition> localDnFilterConditions, String searchBaseDN) {
        List<ConfigProperties.TargetConfig.LocalDnFilter> localFilters = configProperties.getTargetConfig().getLocalDnFilters() != null ?
                configProperties.getTargetConfig().getLocalDnFilters() : Collections.emptyList();
        logger.debug("Local filters configured: {}", localFilters);

        if (localFilters.isEmpty()) {
            logger.debug("No local-dn-filters configured, returning original filter: {}", filter);
            return filter;
        }

        if (filter.getFilterType() == Filter.FILTER_TYPE_AND || filter.getFilterType() == Filter.FILTER_TYPE_OR) {
            List<Filter> remainingComponents = new ArrayList<>();
            List<Filter> subComponents = new ArrayList<>(Arrays.asList(filter.getComponents()));
            String conditionType = filter.getFilterType() == Filter.FILTER_TYPE_AND ? "AND" : "OR";

            if (filter.getFilterType() == Filter.FILTER_TYPE_OR) {
                if (subComponents.size() == 1 && subComponents.get(0).getFilterType() == Filter.FILTER_TYPE_EQUALITY) {
                    Filter subFilter = subComponents.get(0);
                    String attributeName = subFilter.getAttributeName();
                    Optional<ConfigProperties.TargetConfig.LocalDnFilter> matchedConfig = localFilters.stream()
                            .filter(config -> config.getAttribute().equalsIgnoreCase(attributeName))
                            .findFirst();
                    if (matchedConfig.isPresent()) {
                        String value = subFilter.getAssertionValue();
                        boolean autoBaseDn = matchedConfig.get().isAutoBaseDn();
                        if (!isValidDnFilter(value, autoBaseDn)) {
                            logger.warn("Invalid DN filter for attribute {}: {}, rejecting single OR condition", attributeName, value);
                            return Filter.createEqualityFilter("objectClass", "invalid");
                        }
                        if (autoBaseDn) {
                            value = appendBaseDNIfMissing(value, searchBaseDN);
                        }
                        localDnFilterConditions.add(new LocalDnFilterCondition("SIMPLE", attributeName, Collections.singletonList(value), autoBaseDn));
                        logger.debug("Extracted single OR as SIMPLE local filter condition: filterType=DN, attribute={}, autoBaseDn={}, value={}", attributeName, autoBaseDn, value);
                        return null;
                    } else {
                        logger.debug("No matching local filter for attribute {}, preserving subfilter: {}", attributeName, subFilter);
                        remainingComponents.add(subFilter);
                    }
                } else {
                    List<String> orValues = new ArrayList<>();
                    String matchedAttribute = null;
                    Boolean matchedAutoBaseDn = null;
                    boolean allLocalFilters = true;
                    boolean hasValidFilter = false;

                    for (Filter subFilter : subComponents) {
                        if (subFilter.getFilterType() == Filter.FILTER_TYPE_EQUALITY) {
                            String attributeName = subFilter.getAttributeName();
                            Optional<ConfigProperties.TargetConfig.LocalDnFilter> matchedConfig = localFilters.stream()
                                    .filter(config -> config.getAttribute().equalsIgnoreCase(attributeName))
                                    .findFirst();
                            if (matchedConfig.isPresent()) {
                                String value = subFilter.getAssertionValue();
                                boolean autoBaseDn = matchedConfig.get().isAutoBaseDn();
                                if (!isValidDnFilter(value, autoBaseDn)) {
                                    logger.warn("Invalid DN filter for attribute {}: {}, skipping in OR", attributeName, value);
                                    continue;
                                }
                                hasValidFilter = true;
                                if (matchedAttribute == null) {
                                    matchedAttribute = attributeName;
                                    matchedAutoBaseDn = autoBaseDn;
                                } else if (!matchedAttribute.equalsIgnoreCase(attributeName)) {
                                    allLocalFilters = false;
                                    remainingComponents.add(subFilter);
                                    continue;
                                }
                                if (matchedAutoBaseDn != null && matchedAutoBaseDn) {
                                    value = appendBaseDNIfMissing(value, searchBaseDN);
                                }
                                orValues.add(value);
                            } else {
                                allLocalFilters = false;
                                remainingComponents.add(subFilter);
                                continue;
                            }
                        } else {
                            allLocalFilters = false;
                            remainingComponents.add(subFilter);
                            continue;
                        }
                    }

                    if (allLocalFilters && hasValidFilter) {
                        localDnFilterConditions.add(new LocalDnFilterCondition("OR", matchedAttribute, orValues, matchedAutoBaseDn));
                        logger.debug("Extracted OR local filter condition: filterType=DN, attribute={}, autoBaseDn={}, values={}", matchedAttribute, matchedAutoBaseDn, orValues);
                        return null;
                    } else if (allLocalFilters && !hasValidFilter) {
                        logger.warn("All OR subfilters for attribute {} are invalid, rejecting OR condition", matchedAttribute);
                        return Filter.createEqualityFilter("objectClass", "invalid");
                    } else {
                        logger.debug("OR filter contains non-local subfilters, preserving original OR filter");
                        return filter;
                    }
                }
            }

            for (Filter subFilter : subComponents) {
                if (subFilter.getFilterType() == Filter.FILTER_TYPE_AND || subFilter.getFilterType() == Filter.FILTER_TYPE_OR) {
                    Filter transformedSubFilter = extractLocalFilters(subFilter, localDnFilterConditions, searchBaseDN);
                    if (transformedSubFilter != null) {
                        remainingComponents.add(transformedSubFilter);
                    }
                } else if (subFilter.getFilterType() == Filter.FILTER_TYPE_NOT) {
                    Filter notSubFilter = subFilter.getNOTComponent();
                    if (notSubFilter.getFilterType() == Filter.FILTER_TYPE_EQUALITY) {
                        String attributeName = notSubFilter.getAttributeName();
                        Optional<ConfigProperties.TargetConfig.LocalDnFilter> matchedConfig = localFilters.stream()
                                .filter(config -> config.getAttribute().equalsIgnoreCase(attributeName))
                                .findFirst();
                        if (matchedConfig.isPresent()) {
                            String value = notSubFilter.getAssertionValue();
                            boolean autoBaseDn = matchedConfig.get().isAutoBaseDn();
                            if (!isValidDnFilter(value, autoBaseDn)) {
                                logger.warn("Invalid DN filter in NOT for attribute {}: {}, rejecting NOT condition", attributeName, value);
                                return Filter.createEqualityFilter("objectClass", "invalid");
                            }
                            if (autoBaseDn) {
                                value = appendBaseDNIfMissing(value, searchBaseDN);
                            }
                            localDnFilterConditions.add(new LocalDnFilterCondition("NOT", attributeName, Collections.singletonList(value), autoBaseDn));
                            logger.debug("Extracted NOT local filter condition: filterType=DN, attribute={}, autoBaseDn={}, value={}", attributeName, autoBaseDn, value);
                            continue;
                        }
                    }
                    remainingComponents.add(subFilter);
                } else if (subFilter.getFilterType() == Filter.FILTER_TYPE_EQUALITY) {
                    String attributeName = subFilter.getAttributeName();
                    Optional<ConfigProperties.TargetConfig.LocalDnFilter> matchedConfig = localFilters.stream()
                            .filter(config -> config.getAttribute().equalsIgnoreCase(attributeName))
                            .findFirst();
                    if (matchedConfig.isPresent()) {
                        String value = subFilter.getAssertionValue();
                        boolean autoBaseDn = matchedConfig.get().isAutoBaseDn();
                        if (!isValidDnFilter(value, autoBaseDn)) {
                            logger.warn("Invalid DN filter for attribute {}: {}, rejecting SIMPLE condition", attributeName, value);
                            return Filter.createEqualityFilter("objectClass", "invalid");
                        }
                        if (autoBaseDn) {
                            value = appendBaseDNIfMissing(value, searchBaseDN);
                        }
                        localDnFilterConditions.add(new LocalDnFilterCondition("SIMPLE", attributeName, Collections.singletonList(value), autoBaseDn));
                        logger.debug("Extracted SIMPLE local filter condition: filterType=DN, attribute={}, autoBaseDn={}, value={}", attributeName, autoBaseDn, value);
                        continue;
                    }
                    remainingComponents.add(subFilter);
                } else {
                    remainingComponents.add(subFilter);
                }
            }

            if (remainingComponents.isEmpty()) {
                return null;
            }

            if (filter.getFilterType() == Filter.FILTER_TYPE_AND) {
                return Filter.createANDFilter(remainingComponents);
            } else {
                return Filter.createORFilter(remainingComponents);
            }
        } else if (filter.getFilterType() == Filter.FILTER_TYPE_NOT) {
            Filter notSubFilter = filter.getNOTComponent();
            if (notSubFilter.getFilterType() == Filter.FILTER_TYPE_EQUALITY) {
                String attributeName = notSubFilter.getAttributeName();
                Optional<ConfigProperties.TargetConfig.LocalDnFilter> matchedConfig = localFilters.stream()
                        .filter(config -> config.getAttribute().equalsIgnoreCase(attributeName))
                        .findFirst();
                if (matchedConfig.isPresent()) {
                    String value = notSubFilter.getAssertionValue();
                    boolean autoBaseDn = matchedConfig.get().isAutoBaseDn();
                    if (!isValidDnFilter(value, autoBaseDn)) {
                        logger.warn("Invalid DN filter in NOT for attribute {}: {}, rejecting NOT condition", attributeName, value);
                        return Filter.createEqualityFilter("objectClass", "invalid");
                    }
                    if (autoBaseDn) {
                        value = appendBaseDNIfMissing(value, searchBaseDN);
                    }
                    localDnFilterConditions.add(new LocalDnFilterCondition("NOT", attributeName, Collections.singletonList(value), autoBaseDn));
                    logger.debug("Extracted NOT local filter condition: filterType=DN, attribute={}, autoBaseDn={}, value={}", attributeName, autoBaseDn, value);
                    return null;
                }
            }
            return filter;
        } else if (filter.getFilterType() == Filter.FILTER_TYPE_EQUALITY) {
            String attributeName = filter.getAttributeName();
            Optional<ConfigProperties.TargetConfig.LocalDnFilter> matchedConfig = localFilters.stream()
                    .filter(config -> config.getAttribute().equalsIgnoreCase(attributeName))
                    .findFirst();
            if (matchedConfig.isPresent()) {
                String value = filter.getAssertionValue();
                boolean autoBaseDn = matchedConfig.get().isAutoBaseDn();
                if (!isValidDnFilter(value, autoBaseDn)) {
                    logger.warn("Invalid DN filter for attribute {}: {}, rejecting SIMPLE condition", attributeName, value);
                    return Filter.createEqualityFilter("objectClass", "invalid");
                }
                if (autoBaseDn) {
                    value = appendBaseDNIfMissing(value, searchBaseDN);
                }
                localDnFilterConditions.add(new LocalDnFilterCondition("SIMPLE", attributeName, Collections.singletonList(value), autoBaseDn));
                logger.debug("Extracted SIMPLE local filter condition: filterType=DN, attribute={}, autoBaseDn={}, value={}", attributeName, autoBaseDn, value);
                return null;
            }
        }
        return filter;
    }


    public FilterResult generateLdapFilter(Filter originalFilter, String searchBaseDN) {
        long startTime = System.currentTimeMillis();
        logger.debug("Starting generateLdapFilter with originalFilter: {}", originalFilter);
        List<ConfigProperties.TargetConfig.LocalAttribute> attributesList;
        try {
            attributesList = configProperties.getTargetConfig().getLocalAttributes();
        } catch (Exception e) {
            logger.error("Failed to load local attributes", e);
            throw new RuntimeException("Failed to load local attributes", e);
        }
        if (attributesList.isEmpty()) {
            logger.warn("No local attributes configured in local.ldap.target.local-attributes");
        } else {
            logger.debug("Loaded local attributes: {}", attributesList);
        }
        Map<String, ConfigProperties.TargetConfig.LocalAttribute> attributeMap = attributesList.stream()
                .collect(Collectors.toMap(attr -> attr.getName().toLowerCase(), attr -> attr));
        List<LocalDnFilterCondition> localDnFilterConditions = new ArrayList<>();

        // Шаг 1: Проверка доменов
        logger.debug("Step 1: Starting checkDomainInFilter");
        long step1Start = System.currentTimeMillis();
        Filter modifiedFilter;
        try {
            modifiedFilter = checkDomainInFilter(originalFilter, attributesList);
        } catch (Exception e) {
            logger.error("Error in checkDomainInFilter", e);
            throw new RuntimeException("Error in checkDomainInFilter", e);
        }
        logger.debug("checkDomainInFilter took {} ms", System.currentTimeMillis() - step1Start);
        if (modifiedFilter != null) {
            logger.debug("checkDomainInFilter returned modified filter: {}", modifiedFilter);
            if (isInvalidFilter(modifiedFilter)) {
                logger.debug("Filter is invalid (contains objectClass=invalid), rejecting search");
                return new FilterResult(Filter.createEqualityFilter("objectClass", "invalid"), Collections.emptyList(), localDnFilterConditions);
            }
            return new FilterResult(modifiedFilter, Collections.emptyList(), localDnFilterConditions);
        }

        // Шаг 2: Извлечение значений
        logger.debug("Step 2: Starting extractValueFromFilter");
        long step2Start = System.currentTimeMillis();
        List<Map.Entry<String, String>> filterValues;
        try {
            filterValues = extractValueFromFilter(originalFilter, attributeMap);
        } catch (Exception e) {
            logger.error("Error in extractValueFromFilter", e);
            throw new RuntimeException("Error in extractValueFromFilter", e);
        }
        logger.debug("extractValueFromFilter took {} ms", System.currentTimeMillis() - step2Start);
        if (!filterValues.isEmpty()) {
            logger.debug("Extracted filter values: {}", filterValues);
        }

        // Шаг 3: Извлечение локальных фильтров
        logger.debug("Step 3: Starting extractLocalFilters");
        long step3Start = System.currentTimeMillis();
        Filter transformedFilter;
        try {
            transformedFilter = extractLocalFilters(originalFilter, localDnFilterConditions, searchBaseDN);
        } catch (Exception e) {
            logger.warn("Error in extractLocalFilters, rejecting filter: {}", originalFilter, e);
            return new FilterResult(Filter.createEqualityFilter("objectClass", "invalid"), Collections.emptyList(), localDnFilterConditions);
        }
        logger.debug("extractLocalFilters took {} ms", System.currentTimeMillis() - step3Start);
        if (transformedFilter == null) {
            transformedFilter = Filter.createPresenceFilter("objectclass");
            logger.debug("All filters extracted for local filtering, using (objectclass=*) for server query");
        }

        // Шаг 4: Преобразование фильтра
        logger.debug("Step 4: Starting transformFilter with filter: {}", transformedFilter);
        long step4Start = System.currentTimeMillis();
        Filter finalFilter;
        try {
            finalFilter = transformFilter(transformedFilter, attributeMap);
        } catch (Exception e) {
            logger.error("Error in transformFilter", e);
            throw new RuntimeException("Error in transformFilter", e);
        }
        logger.debug("transformFilter took {} ms", System.currentTimeMillis() - step4Start);

        logger.debug("Total generateLdapFilter took {} ms", System.currentTimeMillis() - startTime);
        return new FilterResult(finalFilter, filterValues, localDnFilterConditions);
    }


    private String appendBaseDNIfMissing(String value, String searchBaseDN) {
        String baseDN = searchBaseDN != null && !searchBaseDN.isEmpty() ? searchBaseDN : configProperties.getTargetConfig().getDefaultBase();
        if (baseDN == null || baseDN.isEmpty()) {
            logger.warn("No baseDN provided in search request or default-base configuration, skipping auto-base-dn appending for value: {}", value);
            return value;
        }
        if (!value.toLowerCase().endsWith("," + baseDN.toLowerCase())) {
            return value + "," + baseDN;
        }
        return value;
    }

    // Новый метод для рекурсивной обработки фильтров
    private Filter transformPresenceFilters(Filter filter, List<ConfigProperties.TargetConfig.LocalAttribute> attributes) {
        // Если фильтр — это PRESENCE
        if (filter.getFilterType() == Filter.FILTER_TYPE_PRESENCE) {
            String attributeName = filter.getAttributeName();
            ConfigProperties.TargetConfig.LocalAttribute matchingAttr = attributes.stream()
                    .filter(attr -> attr.getName().equalsIgnoreCase(attributeName))
                    .findFirst()
                    .orElse(null);

            if (matchingAttr != null && matchingAttr.getSearchExpression() != null) {
                String targetAttribute = extractAttributeName(matchingAttr.getSearchExpression());
                // Преобразуем (postalAddress=*) в (sAMAccountName=*)
                String transformedFilter = "(" + targetAttribute + "=*)";
                try {
                    Filter finalFilter = Filter.create(transformedFilter);
                    logger.debug("Transformed wildcard filter: {} -> {}", filter, finalFilter);
                    return finalFilter;
                } catch (LDAPException e) {
                    logger.error("Failed to parse transformed wildcard filter: {}", transformedFilter, e);
                    return Filter.createEqualityFilter("objectClass", "invalid");
                }
            }
            return filter;
        }
        // Если фильтр составной (AND или OR), рекурсивно обрабатываем подфильтры
        else if (filter.getFilterType() == Filter.FILTER_TYPE_AND || filter.getFilterType() == Filter.FILTER_TYPE_OR) {
            List<Filter> modifiedComponents = new ArrayList<>();
            for (Filter subFilter : filter.getComponents()) {
                Filter transformedSubFilter = transformPresenceFilters(subFilter, attributes);
                modifiedComponents.add(transformedSubFilter);
            }
            if (filter.getFilterType() == Filter.FILTER_TYPE_AND) {
                return Filter.createANDFilter(modifiedComponents);
            } else {
                return Filter.createORFilter(modifiedComponents);
            }
        }
        // Для остальных типов фильтров вызываем существующую логику
        return replaceLocalAttributes(filter, attributes);
    }


    private Filter replaceLocalAttributes(Filter filter, List<ConfigProperties.TargetConfig.LocalAttribute> attributes) {
        if (filter.getFilterType() == Filter.FILTER_TYPE_EQUALITY) {
            String attributeName = filter.getAttributeName();
            ConfigProperties.TargetConfig.LocalAttribute matchingAttr = attributes.stream()
                    .filter(attr -> attr.getName().equalsIgnoreCase(attributeName))
                    .findFirst()
                    .orElse(null);

            if (matchingAttr != null && matchingAttr.getSearchExpression() != null) {
                String username = extractUsernameFromValue(filter.getAssertionValue());
                if (username != null && !username.isEmpty()) {
                    String targetAttribute = extractAttributeName(matchingAttr.getSearchExpression());
                    String targetValue = formatServerFilterValue(matchingAttr.getSearchExpression(), username);
                    logger.debug("Replacing local attribute '{}' with server filter for '{}={}'", attributeName, targetAttribute, targetValue);
                    return Filter.createEqualityFilter(targetAttribute, targetValue);
                } else {
                    logger.debug("No valid username found in client filter for '{}', using presence filter for 'mail'", attributeName);
                    return Filter.createPresenceFilter("mail");
                }
            }
            return filter;
        } else if (filter.getFilterType() == Filter.FILTER_TYPE_AND || filter.getFilterType() == Filter.FILTER_TYPE_OR) {
            List<Filter> modifiedFilters = new ArrayList<>();
            for (Filter subFilter : filter.getComponents()) {
                Filter modifiedSubFilter = replaceLocalAttributes(subFilter, attributes);
                modifiedFilters.add(modifiedSubFilter);
            }
            return filter.getFilterType() == Filter.FILTER_TYPE_AND
                    ? Filter.createANDFilter(modifiedFilters)
                    : Filter.createORFilter(modifiedFilters);
        } else if (filter.getFilterType() == Filter.FILTER_TYPE_NOT) {
            Filter subFilter = filter.getNOTComponent();
            Filter modifiedSubFilter = replaceLocalAttributes(subFilter, attributes);
            return Filter.createNOTFilter(modifiedSubFilter);
        }
        return filter;
    }

    private Filter checkDomainInFilter(Filter filter, List<ConfigProperties.TargetConfig.LocalAttribute> localAttributes) {
        if (filter.getFilterType() == Filter.FILTER_TYPE_PRESENCE) {
            String attributeName = filter.getAttributeName().toLowerCase();
            Optional<ConfigProperties.TargetConfig.LocalAttribute> matchedAttribute = localAttributes.stream()
                    .filter(attr -> attr.getName().equalsIgnoreCase(attributeName) && attr.isLocalDomainsOnly())
                    .findFirst();
            if (matchedAttribute.isPresent()) {
                // Для фильтров типа PRESENCE (например, postalAddress=*) считаем домен валидным,
                // так как значения нет, и мы не можем проверить домен
                return null;
            }
            return null; // Атрибут не требует проверки домена
        } else if (filter.getFilterType() == Filter.FILTER_TYPE_EQUALITY) {
            String attributeName = filter.getAttributeName().toLowerCase();
            Optional<ConfigProperties.TargetConfig.LocalAttribute> matchedAttribute = localAttributes.stream()
                    .filter(attr -> attr.getName().equalsIgnoreCase(attributeName) && attr.isLocalDomainsOnly())
                    .findFirst();

            if (matchedAttribute.isPresent()) {
                String value = filter.getAssertionValue();
                if (value != null && value.contains("@")) {
                    String domain = value.substring(value.indexOf("@") + 1);
                    List<String> localDomains = configProperties.getTargetConfig().getLocalDomains();
                    if (localDomains != null && !localDomains.contains(domain)) {
                        logger.debug("Domain '{}' not in local domains: {}, rejecting filter", domain, localDomains);
                        return Filter.createEqualityFilter("objectClass", "invalid");
                    }
                    return null; // Домен валиден
                }
                return Filter.createEqualityFilter("objectClass", "invalid"); // Нет домена в значении
            }
            return null; // Атрибут не требует проверки домена
        } else if (filter.getFilterType() == Filter.FILTER_TYPE_AND || filter.getFilterType() == Filter.FILTER_TYPE_OR) {
            List<Filter> modifiedComponents = new ArrayList<>();
            boolean allInvalid = true;
            boolean hasValidDomains = false;
            boolean hasDomainAttribute = false;

            for (Filter subFilter : filter.getComponents()) {
                Filter modifiedSubFilter = checkDomainInFilter(subFilter, localAttributes);
                if (modifiedSubFilter != null) {
                    boolean isInvalid = modifiedSubFilter.getFilterType() == Filter.FILTER_TYPE_EQUALITY
                            && "invalid".equals(modifiedSubFilter.getAssertionValue());
                    if (filter.getFilterType() == Filter.FILTER_TYPE_OR && isInvalid) {
                        continue;
                    }
                    modifiedComponents.add(modifiedSubFilter);
                    if (!isInvalid) {
                        allInvalid = false;
                        hasValidDomains = true;
                    }
                } else {
                    modifiedComponents.add(subFilter);
                    allInvalid = false;
                    // Проверяем, содержит ли подфильтр доменные атрибуты
                    if (subFilter.getFilterType() == Filter.FILTER_TYPE_EQUALITY || subFilter.getFilterType() == Filter.FILTER_TYPE_PRESENCE) {
                        String attributeName = subFilter.getAttributeName().toLowerCase();
                        if (localAttributes.stream().anyMatch(attr -> attr.getName().equalsIgnoreCase(attributeName) && attr.isLocalDomainsOnly())) {
                            hasDomainAttribute = true;
                            hasValidDomains = true;
                        }
                    } else if (subFilter.getFilterType() == Filter.FILTER_TYPE_AND || subFilter.getFilterType() == Filter.FILTER_TYPE_OR) {
                        if (containsDomainAttributes(subFilter, localAttributes)) {
                            hasDomainAttribute = true;
                            hasValidDomains = true;
                        }
                    }
                }
            }

            if (modifiedComponents.isEmpty()) {
                logger.debug("All subfilters in OR are invalid, rejecting entire filter");
                return Filter.createEqualityFilter("objectClass", "invalid");
            }

            if (allInvalid) {
                logger.debug("All remaining subfilters are invalid, rejecting entire filter");
                return Filter.createEqualityFilter("objectClass", "invalid");
            }

            Filter newFilter = filter.getFilterType() == Filter.FILTER_TYPE_AND
                    ? Filter.createANDFilter(modifiedComponents)
                    : Filter.createORFilter(modifiedComponents);

            if (hasValidDomains && hasDomainAttribute) {
                logger.debug("Filter contains valid domains, proceeding with transformation: {}", newFilter);
                return null;
            }

            logger.debug("Filter has no valid domains or no domain attributes after processing: {}", newFilter);
            return newFilter;
        } else if (filter.getFilterType() == Filter.FILTER_TYPE_NOT) {
            Filter subFilter = filter.getNOTComponent();
            Filter modifiedSubFilter = checkDomainInFilter(subFilter, localAttributes);

            if (modifiedSubFilter != null) {
                boolean isInvalid = modifiedSubFilter.getFilterType() == Filter.FILTER_TYPE_EQUALITY
                        && "invalid".equals(modifiedSubFilter.getAssertionValue());
                if (isInvalid) {
                    logger.debug("Subfilter in NOT is invalid, converting NOT to a valid filter");
                    return Filter.createPresenceFilter("objectClass");
                }
                return Filter.createNOTFilter(modifiedSubFilter);
            }
            return filter;
        }
        return null;
    }

    private boolean containsDomainAttributes(Filter filter, List<ConfigProperties.TargetConfig.LocalAttribute> localAttributes) {
        if (filter.getFilterType() == Filter.FILTER_TYPE_EQUALITY) {
            String attributeName = filter.getAttributeName().toLowerCase();
            return localAttributes.stream().anyMatch(attr -> attr.getName().equalsIgnoreCase(attributeName) && attr.isLocalDomainsOnly());
        } else if (filter.getFilterType() == Filter.FILTER_TYPE_AND || filter.getFilterType() == Filter.FILTER_TYPE_OR) {
            return Stream.of(filter.getComponents()).anyMatch(subFilter -> containsDomainAttributes(subFilter, localAttributes));
        } else if (filter.getFilterType() == Filter.FILTER_TYPE_NOT) {
            return containsDomainAttributes(filter.getNOTComponent(), localAttributes);
        }
        return false;
    }


    private List<Map.Entry<String, String>> extractValueFromFilter(Filter filter, Map<String, ConfigProperties.TargetConfig.LocalAttribute> attributeMap) {
        List<Map.Entry<String, String>> values = new ArrayList<>();

        if (filter.getFilterType() == Filter.FILTER_TYPE_EQUALITY) {
            String attributeName = filter.getAttributeName().toLowerCase();
            if (attributeMap.containsKey(attributeName)) {
                String value = filter.getAssertionValue();
                logger.debug("Extracted value for attribute '{}': {}", attributeName, value);
                values.add(new AbstractMap.SimpleEntry<>(attributeName, value));
            }
        } else if (filter.getFilterType() == Filter.FILTER_TYPE_AND || filter.getFilterType() == Filter.FILTER_TYPE_OR) {
            for (Filter subFilter : filter.getComponents()) {
                values.addAll(extractValueFromFilter(subFilter, attributeMap));
            }
        }
        return values;
    }


    private String extractUsernameFromValue(String value) {
        if (value != null && value.contains("@")) {
            String username = value.split("@")[0];
            if (!username.isEmpty()) {
                return username;
            }
        }
        return null;
    }

    private String formatServerFilterValue(String searchExpression, String username) {
        if (searchExpression.contains("[[email:username]]")) {
            String result = searchExpression.replace("[[email:username]]", username);
            Pattern pattern = Pattern.compile("\\{\\{[^}]+\\}\\}=");
            Matcher matcher = pattern.matcher(result);
            if (matcher.find()) {
                return matcher.replaceFirst("");
            }
            return result;
        }
        return username;
    }

    private String extractAttributeName(String expression) {
        Pattern pattern = Pattern.compile("\\{\\{([^}]+)\\}\\}");
        Matcher matcher = pattern.matcher(expression);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return "";
    }

    private Set<String> extractAttributesFromExpression(String resultExpression) {
        Set<String> attributes = new HashSet<>();
        if (resultExpression == null) {
            return attributes;
        }

        Pattern pattern = Pattern.compile("\\{\\{([^{}]+)\\}\\}");
        Matcher matcher = pattern.matcher(resultExpression);
        while (matcher.find()) {
            String attr = matcher.group(1).trim();
            attributes.add(attr);
            logger.debug("Extracted dependent attribute from result-expression: {}", attr);
        }
        return attributes;
    }

    private String extractUsernameFromEmail(String email) {
        if (email != null && email.contains("@")) {
            String[] parts = email.split("@");
            if (parts.length == 2 && !parts[0].isEmpty() && !parts[1].isEmpty()) {
                return parts[0];
            }
        }
        return null;
    }

    private boolean isDomainAllowed(String email, String targetDomain, List<String> localDomains) {
        if (email == null || !email.contains("@")) {
            return false;
        }
        String domain = email.split("@")[1];
        return domain.equalsIgnoreCase(targetDomain) || localDomains.stream()
                .anyMatch(domain::equalsIgnoreCase);
    }

    private boolean isDnFormat(String bindDn) {
        return bindDn != null && (bindDn.toLowerCase().contains("dc=") || bindDn.toLowerCase().contains("cn="));
    }

    public String processBindExpression(String dn, String password, LDAPConnection conn) throws LDAPException {
        ConfigProperties.TargetConfig targetConfig = configProperties.getTargetConfig();

        if (isDnFormat(dn)) {
            logger.debug("bindDN '{}' is in DN format, using as is", dn);
            return dn;
        }

        if (targetConfig.isMapLocalDomains()) {
            String username = extractUsernameFromEmail(dn);
            if (username != null) {
                if (isDomainAllowed(dn, targetConfig.getDomain(), targetConfig.getLocalDomains())) {
                    String bindValue = username + "@" + targetConfig.getDomain();
                    logger.debug("Mapped email '{}' to bind value '{}'", dn, bindValue);
                    return bindValue;
                } else {
                    logger.warn("Email '{}' has a domain not in allowed list (target: {}, local: {}), rejecting BIND",
                            dn, targetConfig.getDomain(), targetConfig.getLocalDomains());
                    return null;
                }
            }
        }

        logger.debug("No mapping applied, using original bindDN: {}", dn);
        return dn;
    }

    // Обновленный метод getFilter
    public Predicate<SearchResultEntry> getFilter(List<LocalDnFilterCondition> localDnFilterConditions) {
        return entry -> {
            if (localDnFilterConditions == null || localDnFilterConditions.isEmpty()) {
                logger.debug("No local filter conditions, passing entry DN: {}", entry.getDN());
                return true;
            }

            String baseDN = configProperties.getTargetConfig().getDefaultBase();
            if (baseDN == null || baseDN.isEmpty()) {
                logger.warn("Default baseDN is not configured, skipping DN filtering for entry: {}", entry.getDN());
                return false;
            }

            boolean matches = true;

            for (LocalDnFilterCondition condition : localDnFilterConditions) {
                boolean conditionMatch;
                String attributeName = condition.getAttribute().toLowerCase();
                List<String> targetValues;
                if (attributeName.equals("dn")) {
                    targetValues = Collections.singletonList(entry.getDN().toLowerCase());
                } else {
                    Attribute attr = entry.getAttribute(condition.getAttribute());
                    targetValues = attr != null ? Arrays.asList(attr.getValues()).stream()
                            .map(String::toLowerCase)
                            .collect(Collectors.toList()) : Collections.emptyList();
                }

                logger.debug("Processing condition: type={}, attribute={}, values={}, targetValues={}",
                        condition.getType(), attributeName, condition.getValues(), targetValues);

                if (condition.getValues().isEmpty()) {
                    logger.warn("Empty values for condition type {}, attribute {}, rejecting condition", condition.getType(), condition.getAttribute());
                    conditionMatch = false;
                } else if ("SIMPLE".equals(condition.getType())) {
                    String value = condition.getValues().get(0).toLowerCase();
                    conditionMatch = targetValues.stream().anyMatch(target -> {
                        boolean result = checkDnFilter(target, value, condition.isAutoBaseDn(), baseDN);
                        logger.debug("checkDnFilter for SIMPLE: target={}, value={}, result={}", target, value, result);
                        return result;
                    });
                } else if ("OR".equals(condition.getType())) {
                    conditionMatch = false;
                    for (String value : condition.getValues()) {
                        String finalValue = value.toLowerCase();
                        boolean anyMatch = targetValues.stream().anyMatch(target -> {
                            boolean result = checkDnFilter(target, finalValue, condition.isAutoBaseDn(), baseDN);
                            logger.debug("checkDnFilter for OR: target={}, value={}, result={}", target, finalValue, result);
                            return result;
                        });
                        if (anyMatch) {
                            conditionMatch = true;
                            break;
                        }
                    }
                } else if ("NOT".equals(condition.getType())) {
                    String value = condition.getValues().get(0).toLowerCase();
                    conditionMatch = targetValues.stream().noneMatch(target -> {
                        boolean result = checkDnFilter(target, value, condition.isAutoBaseDn(), baseDN);
                        logger.debug("checkDnFilter for NOT: target={}, value={}, result={}", target, value, result);
                        return result;
                    });
                } else if ("AND".equals(condition.getType())) {
                    conditionMatch = true;
                    for (String value : condition.getValues()) {
                        String finalValue = value.toLowerCase();
                        boolean allMatch = targetValues.stream().anyMatch(target -> {
                            boolean result = checkDnFilter(target, finalValue, condition.isAutoBaseDn(), baseDN);
                            logger.debug("checkDnFilter for AND: target={}, value={}, result={}", target, finalValue, result);
                            return result;
                        });
                        if (!allMatch) {
                            conditionMatch = false;
                            break;
                        }
                    }
                } else {
                    logger.warn("Unsupported condition type: {}", condition.getType());
                    conditionMatch = false;
                }

                if (condition.getType().equals("AND")) {
                    matches &= conditionMatch;
                } else if (condition.getType().equals("OR")) {
                    matches |= conditionMatch;
                } else if (condition.getType().equals("NOT")) {
                    matches = conditionMatch;
                } else {
                    matches &= conditionMatch; // SIMPLE как часть AND
                }

                if (!matches && condition.getType().equals("AND")) {
                    break; // Оптимизация: если AND и уже false, дальше не проверяем
                }
            }

            if (matches) {
                logger.debug("Entry DN matches local filter conditions: {}", entry.getDN());
            } else {
                logger.debug("Entry DN does not match local filter conditions: {}", entry.getDN());
            }
            return matches;
        };
    }

    // Метод для удаления baseDN из DN
    private String removeBaseDN(String dn, String baseDN) {
        if (baseDN == null || baseDN.isEmpty()) {
            return dn;
        }
        if (dn.toLowerCase().endsWith("," + baseDN.toLowerCase())) {
            return dn.substring(0, dn.length() - baseDN.length() - 1);
        }
        return dn;
    }

    // в каждой из вовзращенных сервером записей вычислям локальные атрибуты по значениям серверным
    public BiFunction<SearchResultEntry, Integer, LDAPMessage> getEntryProcessor(List<String> requestedAttributes, List<Map.Entry<String, String>> filterValues) {
        return (entry, messageId) -> {
            Set<String> dependentAttributes = configProperties.getTargetConfig().getLocalAttributes().stream()
                    .map(ConfigProperties.TargetConfig.LocalAttribute::getResultExpression)
                    .filter(Objects::nonNull)
                    .flatMap(expr -> extractAttributesFromExpression(expr).stream())
                    .collect(Collectors.toSet());
            List<Attribute> attributes = new ArrayList<>();
            boolean returnAllAttributes = requestedAttributes == null ||
                    requestedAttributes.isEmpty() ||
                    requestedAttributes.contains("*");

            if (returnAllAttributes) {
                for (Attribute attr : entry.getAttributes()) {
                    attributes.add(attr);
                }
            } else {
                for (String attr : requestedAttributes) {
                    Attribute serverAttr = entry.getAttribute(attr);
                    if (serverAttr != null) {
                        attributes.add(serverAttr);
                    }
                }
            }

            // Добавляем локальные атрибуты, если они запрошены или запрошены все атрибуты
            for (ConfigProperties.TargetConfig.LocalAttribute localAttr : configProperties.getTargetConfig().getLocalAttributes()) {
                String resultExpression = localAttr.getResultExpression();
                if (resultExpression != null) {
                    // Проверяем, запрошен ли этот локальный атрибут
                    boolean isRequested = returnAllAttributes || requestedAttributes.stream()
                            .anyMatch(reqAttr -> reqAttr.equalsIgnoreCase(localAttr.getName()));
                    if (isRequested) {
                        String value = evaluateExpression(resultExpression, entry, null, localAttr);
                        if (value != null) {
                            attributes.add(new Attribute(localAttr.getName(), value));
                            logger.debug("Added local attribute {}={} for clientMessageId: {}", localAttr.getName(), value, messageId);
                        }
                    }
                }
            }

            if (!returnAllAttributes) {
                attributes = attributes.stream()
                        .filter(attr -> {
                            boolean isDependent = dependentAttributes.stream()
                                    .anyMatch(depAttr -> depAttr.equalsIgnoreCase(attr.getName()));
                            boolean isRequested = requestedAttributes.stream()
                                    .anyMatch(reqAttr -> reqAttr.equalsIgnoreCase(attr.getName()));
                            boolean isLocal = configProperties.getTargetConfig().getLocalAttributes().stream()
                                    .anyMatch(localAttr -> localAttr.getName().equalsIgnoreCase(attr.getName()));
                            return isRequested || isLocal || !isDependent;
                        })
                        .collect(Collectors.toList());
            }

            Entry updatedEntry = new Entry(entry.getDN(), attributes);
            SearchResultEntry updatedSearchResultEntry = new SearchResultEntry(updatedEntry);
            SearchResultEntryProtocolOp entryOp = new SearchResultEntryProtocolOp(updatedSearchResultEntry);
            return new LDAPMessage(messageId, entryOp);
        };
    }


    private String parseResultExpression(
        SearchResultEntry entry,
        String expression,
        String filterValue,
        ConfigProperties.TargetConfig.LocalAttribute localAttr
    ) {
        String newValue = expression;
        Set<String> dependentAttrs = extractAttributesFromExpression(expression);
        for (String depAttr : dependentAttrs) {
            String placeholder = "{{" + depAttr + "}}";
            String replacement = entry.getAttributeValue(depAttr);
            if (replacement == null) {
                if (filterValue != null && filterValue.contains("@")) {
                    replacement = filterValue.substring(0, filterValue.indexOf("@"));
                    logger.debug("Using fallback value for {}: {}", depAttr, replacement);
                } else {
                    logger.warn("No value found for dependent attribute {}, skipping expression {}", depAttr, expression);
                    return null;
                }
            }
            newValue = newValue.replace(placeholder, replacement);
        }

        if (localAttr.isLocalDomainsOnly() && newValue.contains("@")) {
            String domain = newValue.substring(newValue.indexOf("@") + 1);
            ConfigProperties.TargetConfig targetConfig = configProperties.getTargetConfig();
            String targetDomain = targetConfig.getDomain();
            List<String> localDomains = targetConfig.getLocalDomains() != null ? targetConfig.getLocalDomains() : Collections.emptyList();

            boolean isDomainAllowed = domain.equalsIgnoreCase(targetDomain) ||
                    localDomains.stream().anyMatch(domain::equalsIgnoreCase);
            if (!isDomainAllowed) {
                logger.warn("Invalid domain in result for attribute {}: {}. Expected target domain: {}, local domains: {}",
                        localAttr.getName(), domain, targetDomain, localDomains);
                return null;
            }
        }
        return newValue;
    }

    public List<String> enhanceRequestedAttributes(List<String> requestedAttributes) {
        List<ConfigProperties.TargetConfig.LocalAttribute> localAttributes = configProperties.getTargetConfig().getLocalAttributes();
        Set<String> localAttributeNames = localAttributes.stream()
                .map(ConfigProperties.TargetConfig.LocalAttribute::getName)
                .map(String::toLowerCase)
                .collect(Collectors.toSet());

        List<String> attributesToRequest = new ArrayList<>();

        // Нормализуем requestedAttributes
        List<String> normalizedAttributes;
        if (requestedAttributes == null) {
            normalizedAttributes = Collections.singletonList("*");
            logger.debug("requestedAttributes is null, assuming all attributes requested: {}", normalizedAttributes);
        } else {
            normalizedAttributes = new ArrayList<>(requestedAttributes);
            // Проверяем, есть ли подозрительные элементы, которые могут быть именами файлов
            boolean hasSuspiciousAttributes = normalizedAttributes.stream()
                .anyMatch(
                attr -> attr.contains(".") || attr.contains("/") || attr.contains("\\")
                );
            if (hasSuspiciousAttributes) {
                logger.warn("Requested attributes contain elements that look like filenames: {}. This might be due to unescaped '*' in the command line.", normalizedAttributes);
            }
            logger.debug("Requested attributes: {}", normalizedAttributes);
        }

        // Шаг 1: Собираем все зависимые атрибуты, необходимые для локальных вычислений
        Set<String> dependentAttributes = new HashSet<>();
        for (ConfigProperties.TargetConfig.LocalAttribute attr : localAttributes) {
            if (attr.getResultExpression() != null) {
                Set<String> attrNames = extractAttributeNames(attr.getResultExpression());
                for (String depAttr : attrNames) {
                    if (!depAttr.equals("*")) {
                        dependentAttributes.add(depAttr);
                        logger.debug("Added dependent attribute for local computation: {}", depAttr);
                    }
                }
            }
        }

        // Шаг 2: Проверяем, есть ли "*" или пустой список
        if (normalizedAttributes.isEmpty() || normalizedAttributes.contains("*")) {
            attributesToRequest.add("*");
            attributesToRequest.addAll(dependentAttributes);
            logger.debug("Client requested '*' or no attributes, requesting all server attributes plus dependent attributes: {}", attributesToRequest);
            return attributesToRequest;
        }

        // Шаг 3: Фильтруем запрошенные атрибуты, исключая локальные
        Set<String> filteredAttributes = normalizedAttributes.stream()
                .filter(attr -> !localAttributeNames.contains(attr.toLowerCase()))
                .collect(Collectors.toSet());
        logger.debug("Filtered requested attributes (excluding local attributes): {}", filteredAttributes);

        // Шаг 4: Добавляем зависимые атрибуты для запрошенных локальных атрибутов
        for (ConfigProperties.TargetConfig.LocalAttribute attr : localAttributes) {
            boolean isRequested = normalizedAttributes.stream()
                    .anyMatch(reqAttr -> reqAttr.equalsIgnoreCase(attr.getName()));
            if (isRequested && attr.getResultExpression() != null) {
                Set<String> attrNames = extractAttributeNames(attr.getResultExpression());
                for (String depAttr : attrNames) {
                    if (!depAttr.equals("*") && !filteredAttributes.contains(depAttr)) {
                        dependentAttributes.add(depAttr);
                        logger.debug("Added dependent attribute for local computation: {}", depAttr);
                    }
                }
            }
        }

        // Шаг 5: Формируем итоговый список
        attributesToRequest.addAll(filteredAttributes);
        attributesToRequest.addAll(dependentAttributes);
        if (attributesToRequest.isEmpty()) {
            attributesToRequest.add("objectClass");
            logger.debug("No attributes to request after filtering, added default: objectClass");
        }

        logger.debug("Final attributes to request from server: {}", attributesToRequest);
        return attributesToRequest;
    }



    public List<String> enhanceRequestedAttributes01(List<String> requestedAttributes) {
        List<ConfigProperties.TargetConfig.LocalAttribute> localAttributes = configProperties.getTargetConfig().getLocalAttributes();
        Set<String> localAttributeNames = localAttributes.stream()
                .map(ConfigProperties.TargetConfig.LocalAttribute::getName)
                .map(String::toLowerCase)
                .collect(Collectors.toSet());

        List<String> attributesToRequest = new ArrayList<>();

        // Шаг 1: Собираем все зависимые атрибуты, необходимые для локальных вычислений
        Set<String> dependentAttributes = new HashSet<>();
        for (ConfigProperties.TargetConfig.LocalAttribute attr : localAttributes) {
            if (attr.getResultExpression() != null) {
                Set<String> attrNames = extractAttributeNames(attr.getResultExpression());
                for (String depAttr : attrNames) {
                    if (!depAttr.equals("*")) {
                        dependentAttributes.add(depAttr);
                        logger.debug("Added dependent attribute for local computation: {}", depAttr);
                    }
                }
            }
        }

        // Шаг 2: Проверяем, есть ли "*" или пустой список
        if (requestedAttributes == null || requestedAttributes.isEmpty() || requestedAttributes.contains("*")) {
            attributesToRequest.add("*");
            // Добавляем зависимые атрибуты, чтобы гарантировать их наличие
            attributesToRequest.addAll(dependentAttributes);
            logger.debug("Client requested '*' or no attributes, requesting all server attributes plus dependent attributes: {}", attributesToRequest);
            return attributesToRequest;
        }

        // Шаг 3: Фильтруем запрошенные атрибуты, исключая локальные
        Set<String> filteredAttributes = requestedAttributes.stream()
                .filter(attr -> !localAttributeNames.contains(attr.toLowerCase()))
                .collect(Collectors.toSet());
        logger.debug("Filtered requested attributes (excluding local attributes): {}", filteredAttributes);

        // Шаг 4: Добавляем зависимые атрибуты для запрошенных локальных атрибутов
        for (ConfigProperties.TargetConfig.LocalAttribute attr : localAttributes) {
            boolean isRequested = requestedAttributes.stream()
                    .anyMatch(reqAttr -> reqAttr.equalsIgnoreCase(attr.getName()));
            if (isRequested && attr.getResultExpression() != null) {
                Set<String> attrNames = extractAttributeNames(attr.getResultExpression());
                for (String depAttr : attrNames) {
                    if (!depAttr.equals("*") && !filteredAttributes.contains(depAttr)) {
                        dependentAttributes.add(depAttr);
                        logger.debug("Added dependent attribute for local computation: {}", depAttr);
                    }
                }
            }
        }

        // Шаг 5: Формируем итоговый список
        attributesToRequest.addAll(filteredAttributes);
        attributesToRequest.addAll(dependentAttributes);
        if (attributesToRequest.isEmpty()) {
            attributesToRequest.add("objectClass");
            logger.debug("No attributes to request after filtering, added default: objectClass");
        }

        logger.debug("Final attributes to request from server: {}", attributesToRequest);
        return attributesToRequest;
    }

    private Set<String> extractAttributeNames(String resultExpression) {
        Set<String> attributeNames = new HashSet<>();
        if (resultExpression != null) {
            Pattern pattern = Pattern.compile("\\{\\{([^{}]+)\\}\\}");
            Matcher matcher = pattern.matcher(resultExpression);
            while (matcher.find()) {
                attributeNames.add(matcher.group(1).trim());
            }
        }
        return attributeNames;
    }

    private String evaluateExpression(String resultExpression, SearchResultEntry entry, String filterValue, ConfigProperties.TargetConfig.LocalAttribute localAttr) {
        if (resultExpression == null || entry == null) {
            return null;
        }
        try {
            String result = resultExpression;
            Set<String> attrNames = extractAttributeNames(resultExpression);
            for (String attrName : attrNames) {
                Attribute attr = entry.getAttribute(attrName);
                String value = (attr != null && attr.getValues().length > 0) ? attr.getValues()[0] : null;
                if (value == null) {
                    logger.warn("No value found for dependent attribute {}, skipping expression {}", attrName, resultExpression);
                    return null;
                }
                result = result.replace("{{" + attrName + "}}", value);
            }

            if (localAttr.isLocalDomainsOnly() && result.contains("@")) {
                String domain = result.substring(result.indexOf("@") + 1);
                ConfigProperties.TargetConfig targetConfig = configProperties.getTargetConfig();
                String targetDomain = targetConfig.getDomain();
                List<String> localDomains = targetConfig.getLocalDomains() != null ? targetConfig.getLocalDomains() : Collections.emptyList();

                boolean isDomainAllowed = domain.equalsIgnoreCase(targetDomain) ||
                        localDomains.stream().anyMatch(domain::equalsIgnoreCase);
                if (!isDomainAllowed) {
                    logger.warn("Invalid domain in result for attribute {}: {}. Expected target domain: {}, local domains: {}",
                            localAttr.getName(), domain, targetDomain, localDomains);
                    return null;
                }
            }
            logger.debug("Evaluated expression {} to value: {}", resultExpression, result);
            return result.isEmpty() ? null : result;
        } catch (Exception e) {
            logger.error("Failed to evaluate expression: {}, error: {}", resultExpression, e.getMessage());
            return null;
        }
    }

    private Filter transformFilter(Filter filter, Map<String, ConfigProperties.TargetConfig.LocalAttribute> attributeMap) {
        if (filter.getFilterType() == Filter.FILTER_TYPE_PRESENCE) {
            String attributeName = filter.getAttributeName().toLowerCase();
            logger.debug("Processing PRESENCE filter for attribute '{}'", attributeName);
            ConfigProperties.TargetConfig.LocalAttribute localAttribute = attributeMap.get(attributeName);
            if (localAttribute != null) {
                logger.debug("Found matching local attribute: {}", localAttribute);
                String searchExpression = localAttribute.getSearchExpression();
                if (searchExpression != null) {
                    // Извлекаем целевой атрибут из searchExpression (например, {{sAMAccountName}})
                    String targetAttribute = extractAttributeName(searchExpression);
                    logger.debug("Replacing local attribute '{}' presence filter with '{}=*'", attributeName, targetAttribute);
                    return Filter.createPresenceFilter(targetAttribute);
                }
            }
            logger.debug("No matching local attribute found for '{}', keeping original filter", attributeName);
            return filter;
        } else
        if (filter.getFilterType() == Filter.FILTER_TYPE_EQUALITY) {
            String attributeName = filter.getAttributeName().toLowerCase();
            logger.debug("Processing EQUALITY filter for attribute '{}'", attributeName);
            ConfigProperties.TargetConfig.LocalAttribute localAttribute = attributeMap.get(attributeName);
            if (localAttribute != null) {
                logger.debug("Found matching attribute: {}", localAttribute);
                String value = filter.getAssertionValue();
                String username = value.contains("@") ? value.substring(0, value.indexOf("@")) : value;
                logger.debug("Extracted username: {}", username);

                String searchExpression = localAttribute.getSearchExpression();
                if (searchExpression != null) {
                    String serverFilter = searchExpression.replace("{{sAMAccountName}}", username);
                    logger.debug("Replacing local attribute '{}' with server filter for '{}'", attributeName, serverFilter);
                    return Filter.createEqualityFilter("sAMAccountName", username);
                }
            } else {
                logger.debug("No matching local attribute found for '{}'", attributeName);
            }
            return filter;
        } else if (filter.getFilterType() == Filter.FILTER_TYPE_OR) {
            Set<Filter> transformedComponents = new LinkedHashSet<>(); // Используем Set, чтобы избежать дубликатов
            for (Filter subFilter : filter.getComponents()) {
                Filter transformedSubFilter = transformFilter(subFilter, attributeMap);
                transformedComponents.add(transformedSubFilter);
            }
            List<Filter> uniqueComponents = new ArrayList<>(transformedComponents);
            if (uniqueComponents.size() == 1) {
                return uniqueComponents.get(0); // Если остался один уникальный фильтр, возвращаем его
            }
            return Filter.createORFilter(uniqueComponents);
        } else if (filter.getFilterType() == Filter.FILTER_TYPE_AND) {
            List<Filter> transformedComponents = new ArrayList<>();
            for (Filter subFilter : filter.getComponents()) {
                Filter transformedSubFilter = transformFilter(subFilter, attributeMap);
                transformedComponents.add(transformedSubFilter);
            }
            return Filter.createANDFilter(transformedComponents);
        } else if (filter.getFilterType() == Filter.FILTER_TYPE_NOT) {
            // NOT должен содержать ровно один подфильтр
            Filter subFilter = filter.getNOTComponent();
            Filter transformedSubFilter = transformFilter(subFilter, attributeMap);
            return Filter.createNOTFilter(transformedSubFilter);
        }
        return filter;
    }

}
