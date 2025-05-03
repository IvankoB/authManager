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

/*
Список методов в предоставленном LdapMITM.java:

isValidDnFilter(String value, boolean autoBaseDn)
    — валидация DN-фильтра.
checkDnFilter(String dn, String filterValue, boolean autoBaseDn, String baseDN)
    — проверка соответствия DN фильтру.
isInvalidFilter(Filter filter)
    — проверка, является ли фильтр недопустимым (objectClass=invalid).
extractLocalFilters(Filter filter, List<LocalDnFilterCondition> localDnFilterConditions, String searchBaseDN)
    — извлечение локальных фильтров.
appendBaseDNIfMissing(String value, String searchBaseDN)
    - добавление baseDN к значению, если требуется.
transformPresenceFilters(Filter filter, List<ConfigProperties.TargetConfig.LocalAttribute> attributes)
    — трансформация фильтров типа PRESENCE.
replaceLocalAttributes(Filter filter, List<ConfigProperties.TargetConfig.LocalAttribute> attributes)
    — замена локальных атрибутов.
checkDomainInFilter(Filter filter, List<ConfigProperties.TargetConfig.LocalAttribute> localAttributes)
    — проверка доменов в фильтре.
containsDomainAttributes(Filter filter, List<ConfigProperties.TargetConfig.LocalAttribute> localAttributes)
    — проверка наличия доменных атрибутов.
extractValueFromFilter(Filter filter, Map<String, ConfigProperties.TargetConfig.LocalAttribute> attributeMap)
    — извлечение значений из фильтра.
extractUsernameFromValue(String value)
    — извлечение имени пользователя из значения.
formatServerFilterValue(String searchExpression, String username)
    — форматирование значения серверного фильтра.
extractAttributeName(String expression)
    — извлечение имени атрибута из выражения.
extractAttributesFromExpression(String resultExpression)
    — извлечение атрибутов из выражения.
extractUsernameFromEmail(String email)
    — извлечение имени пользователя из email.
isDomainAllowed(String email, String targetDomain, List<String> localDomains)
    — проверка допустимости домена.
isDnFormat(String bindDn)
    — проверка формата DN.
processBindExpression(String dn, String password, LDAPConnection conn)
    — обработка BIND-выражения.
getFilter(FilterExtractionResult extractionResult)
    — получение предиката для фильтрации записей.
removeBaseDN(String dn, String baseDN)
    — удаление baseDN из DN.
getEntryProcessor(List<String> requestedAttributes, List<Map.Entry<String, String>> filterValues)
    — обработка LDAP-записей.
parseResultExpression(SearchResultEntry entry, String expression, String filterValue, ConfigProperties.TargetConfig.LocalAttribute localAttr)
    — парсинг выражения результата.
enhanceRequestedAttributes(List<String> requestedAttributes)
    — расширение запрошенных атрибутов.
enhanceRequestedAttributes01(List<String> requestedAttributes)
    — альтернативная версия enhanceRequestedAttributes.
extractAttributeNames(String resultExpression)
    — извлечение имён атрибутов из выражения.
evaluateExpression(String resultExpression, SearchResultEntry entry, String filterValue, ConfigProperties.TargetConfig.LocalAttribute localAttr)
    — вычисление выражения.
transformFilter(Filter filter, Map<String, ConfigProperties.TargetConfig.LocalAttribute> attributeMap)
    — трансформация фильтра.
generateLdapFilter(Filter originalFilter, String searchBaseDN)
    — генерация LDAP-фильтра (восстановленный метод).
*/

@Component
public class LdapMITM {
    private static final Logger logger = LoggerFactory.getLogger(LdapMITM.class);

    private final ConfigProperties configProperties;

    public enum DN_FILTER_TYPE {
        EQUALITY,  // Проверка равенства, например, (dn=ou=IT)
        ANY,       // Проверка наличия атрибута/DN, например, (dn=*)
        OR,        // Логическое ИЛИ, например, (|(dn=ou=IT)(dn=ou=Staff))
        AND,       // Логическое И, например, (&(dn=ou=IT)(dn=cn=*))
        NOT;       // Логическое НЕ, например, (!(dn=ou=Staff))

        // Проверяет, является ли тип логическим оператором (OR, AND, NOT)
        public boolean isLogicalOperator() {
            return this == OR || this == AND || this == NOT;
        }

        // Проверяет, является ли тип одиночным условием (EQUALITY, ANY)
        public boolean isSingleCondition() {
            return this == EQUALITY || this == ANY;
        }

        // Преобразование в строковое представление для логирования или сериализации
        @Override
        public String toString() {
            return name();
        }
    }


    public enum DnFilterValidationResult {
        VALID, NULL_VALUE, EMPTY_COMPONENTS, INVALID_COMPONENT, INVALID_KEY, NON_ALPHABETIC_KEY, EMPTY_VALUE, MISSING_DC;

        public static boolean isValid(Set<DnFilterValidationResult> results) {
            return results.isEmpty() || results.contains(VALID);
        }

        public static boolean isValidForOr(List<Set<DnFilterValidationResult>> resultsList) {
            return resultsList.stream().anyMatch(DnFilterValidationResult::isValid);
        }

        public static boolean isValidForAnd(List<Set<DnFilterValidationResult>> resultsList) {
            return resultsList.stream().allMatch(DnFilterValidationResult::isValid);
        }

        public static boolean isValidForNot(Set<DnFilterValidationResult> results) {
            return isValid(results);
        }

        public static boolean isValidForAny(Set<DnFilterValidationResult> results) {
            return isValid(results);
        }

        public static boolean isValidForEquality(Set<DnFilterValidationResult> results) {
            return isValid(results);
        }

        public static boolean hasInvalidKey(Set<DnFilterValidationResult> results) {
            return results.contains(INVALID_KEY);
        }

        public static boolean hasEmptyValue(Set<DnFilterValidationResult> results) {
            return results.contains(EMPTY_VALUE);
        }

        public static boolean hasInvalidComponent(Set<DnFilterValidationResult> results) {
            return results.contains(INVALID_COMPONENT) || results.contains(EMPTY_COMPONENTS) || results.contains(NULL_VALUE);
        }

        public static String getValidationIssues(Set<DnFilterValidationResult> results) {
            if (isValid(results)) {
                return "VALID";
            }
            return results.stream()
                    .map(Enum::toString)
                    .collect(Collectors.joining(" | "));
        }
    }

    public enum DnFilterCheckResult {
        MATCH, INVALID_INPUT, INSUFFICIENT_COMPONENTS, INVALID_COMPONENT_FORMAT, KEY_MISMATCH, VALUE_MISMATCH, UNMATCHED_FILTER_COMPONENTS;

        public static boolean isMatch(Set<DnFilterCheckResult> results) {
            return results.isEmpty() || results.contains(MATCH);
        }

        public static boolean isMatchForOr(List<Set<DnFilterCheckResult>> resultsList) {
            return resultsList.stream().anyMatch(DnFilterCheckResult::isMatch);
        }

        public static boolean isMatchForAnd(List<Set<DnFilterCheckResult>> resultsList) {
            return resultsList.stream().allMatch(DnFilterCheckResult::isMatch);
        }

        public static boolean isMatchForNot(Set<DnFilterCheckResult> results) {
            return !isMatch(results);
        }

        public static boolean isMatchForAny(Set<DnFilterCheckResult> results) {
            return isMatch(results);
        }

        public static boolean isMatchForEquality(Set<DnFilterCheckResult> results) {
            return isMatch(results);
        }

        public static boolean hasKeyMismatch(Set<DnFilterCheckResult> results) {
            return results.contains(KEY_MISMATCH);
        }

        public static boolean hasValueMismatch(Set<DnFilterCheckResult> results) {
            return results.contains(VALUE_MISMATCH);
        }

        public static boolean hasComponentIssue(Set<DnFilterCheckResult> results) {
            return results.contains(INSUFFICIENT_COMPONENTS) ||
                    results.contains(INVALID_COMPONENT_FORMAT) ||
                    results.contains(UNMATCHED_FILTER_COMPONENTS);
        }

        public static String getCheckIssues(Set<DnFilterCheckResult> results) {
            if (isMatch(results)) {
                return "MATCH";
            }
            return results.stream()
                    .map(Enum::toString)
                    .collect(Collectors.joining(" | "));
        }
    }

    @Data
    public static class LocalDnFilterCondition {
        private final DN_FILTER_TYPE type;
        private final String attribute;
        private final List<String> values;
        private final boolean autoBaseDn;
        private final boolean invalid; // New field

        public LocalDnFilterCondition(DN_FILTER_TYPE type, String attribute, List<String> values, boolean autoBaseDn, boolean invalid) {
            this.type = type;
            this.attribute = attribute;
            this.values = values != null ? new ArrayList<>(values) : new ArrayList<>();
            this.autoBaseDn = autoBaseDn;
            this.invalid = invalid;
        }

//        public boolean isInvalid() {
//            return invalid;
//        }

        public LocalDnFilterCondition(DN_FILTER_TYPE type, String attribute, List<String> values, boolean autoBaseDn) {
            this(type, attribute, values, autoBaseDn, false);
        }
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

    public static class FilterExtractionResult {
        private final List<LocalDnFilterCondition> conditions;
        private final Filter remainingFilter;
        private final boolean rejectedDueToInvalidFilter;

        public FilterExtractionResult(List<LocalDnFilterCondition> conditions, Filter remainingFilter, boolean rejectedDueToInvalidFilter) {
            this.conditions = conditions;
            this.remainingFilter = remainingFilter;
            this.rejectedDueToInvalidFilter = rejectedDueToInvalidFilter;
        }

        public List<LocalDnFilterCondition> getConditions() {
            return conditions;
        }

        public Filter getRemainingFilter() {
            return remainingFilter;
        }

        public boolean isRejectedDueToInvalidFilter() {
            return rejectedDueToInvalidFilter;
        }
    }

    @Autowired
    public LdapMITM(ConfigProperties configProperties) {
        this.configProperties = configProperties;
    }

    // Валидация DN-фильтра
    private Set<DnFilterValidationResult> isValidDnFilter(String value, boolean autoBaseDn) {
        Set<DnFilterValidationResult> results = new HashSet<>();

        if (value == null) {
            logger.debug("DN filter validation failed: value is null");
            results.add(DnFilterValidationResult.NULL_VALUE);
            return results;
        }

        String[] components = value.split(",");
        if (components.length == 0) {
            logger.debug("DN filter validation failed: no components");
            results.add(DnFilterValidationResult.EMPTY_COMPONENTS);
            return results;
        }

        boolean hasDc = false;
        for (String component : components) {
            if (!component.contains("=")) {
                logger.debug("DN filter validation failed: component without '=': {}", component);
                results.add(DnFilterValidationResult.INVALID_COMPONENT);
                continue;
            }
            String[] parts = component.split("=", 2);
            if (parts.length != 2) {
                logger.debug("DN filter validation failed: invalid component structure: {}", component);
                results.add(DnFilterValidationResult.INVALID_COMPONENT);
                continue;
            }
            String key = parts[0].trim();
            String val = parts[1].trim();

            if (!key.matches("cn|ou|dc")) {
                logger.debug("DN filter validation failed: invalid key '{}'", key);
                results.add(DnFilterValidationResult.INVALID_KEY);
            }
            if (!key.matches("[a-zA-Z]+")) {
                logger.debug("DN filter validation failed: non-alphabetic key '{}'", key);
                results.add(DnFilterValidationResult.NON_ALPHABETIC_KEY);
            }
            if (key.equals("dc")) hasDc = true;
            if (val.isEmpty()) {
                logger.debug("DN filter validation failed: empty value in component '{}'", component);
                results.add(DnFilterValidationResult.EMPTY_VALUE);
            }
        }

        if (!autoBaseDn && !hasDc) {
            logger.debug("DN filter validation failed: missing dc and autoBaseDn=false");
            results.add(DnFilterValidationResult.MISSING_DC);
        }

        if (results.isEmpty()) {
            results.add(DnFilterValidationResult.VALID);
        }
        return results;
    }


    // Проверка DN на точное соответствие фильтру
    private Set<DnFilterCheckResult> checkDnFilter(String dn, String filterValue, boolean autoBaseDn, String baseDN) {
        Set<DnFilterCheckResult> results = new HashSet<>();

        if (dn == null || filterValue == null || baseDN == null) {
            logger.debug("DN filter check failed: invalid input: dn={}, filterValue={}, baseDN={}", dn, filterValue, baseDN);
            results.add(DnFilterCheckResult.INVALID_INPUT);
            return results;
        }

        // Добавляем baseDN, если требуется
        String fullFilterValue = autoBaseDn && !filterValue.toLowerCase().contains("dc=") ? appendBaseDNIfMissing(filterValue, baseDN) : filterValue;
        String[] filterComponents = fullFilterValue.toLowerCase().split(",");
        String[] dnComponents = dn.toLowerCase().split(",");

        // Проверяем только начало DN
        boolean matched = true;
        for (int i = 0; i < filterComponents.length; i++) {
            int dnIndex = i;
            if (dnIndex >= dnComponents.length) {
                matched = false;
                break;
            }

            String filterComponent = filterComponents[i];
            String dnComponent = dnComponents[dnIndex];

            if (!filterComponent.contains("=") || !dnComponent.contains("=")) {
                logger.debug("DN filter check failed: invalid component format: filterComponent={}, dnComponent={}",
                        filterComponent, dnComponent);
                results.add(DnFilterCheckResult.INVALID_COMPONENT_FORMAT);
                matched = false;
                break;
            }

            String[] filterParts = filterComponent.split("=", 2);
            String[] dnParts = dnComponent.split("=", 2);
            if (filterParts.length != 2 || dnParts.length != 2) {
                logger.debug("DN filter check failed: invalid component structure: filterComponent={}, dnComponent={}",
                        filterComponent, dnComponent);
                results.add(DnFilterCheckResult.INVALID_COMPONENT_FORMAT);
                matched = false;
                break;
            }

            String filterKey = filterParts[0].trim();
            String filterValuePart = filterParts[1].trim();
            String dnKey = dnParts[0].trim();
            String dnValue = dnParts[1].trim();

            logger.debug("Comparing components: filterKey={}, filterValue={}, dnKey={}, dnValue={}",
                    filterKey, filterValuePart, dnKey, dnValue);

            if (!filterKey.equals(dnKey)) {
                matched = false;
                break;
            }

            if (filterValuePart.equals("*")) {
                continue;
            } else if (filterValuePart.contains("*")) {
                String pattern = filterValuePart.replace("*", ".*");
                if (!dnValue.matches(pattern)) {
                    logger.debug("DN filter check failed: value mismatch: dnValue={} does not match pattern={} in filter {}",
                            dnValue, pattern, filterComponent);
                    results.add(DnFilterCheckResult.VALUE_MISMATCH);
                    matched = false;
                    break;
                }
            } else if (!filterValuePart.equals(dnValue)) {
                logger.debug("DN filter check failed: value mismatch: filterValue={} != dnValue={} in components {} and {}",
                        filterValuePart, dnValue, filterComponent, dnComponent);
                results.add(DnFilterCheckResult.VALUE_MISMATCH);
                matched = false;
                break;
            }
        }

        if (matched) {
            logger.debug("DN {} matches filter {} at startIndex 0", dn, fullFilterValue);
            results.add(DnFilterCheckResult.MATCH);
            return results;
        }

        logger.debug("DN {} does not match filter {} at startIndex 0", dn, fullFilterValue);
        results.add(DnFilterCheckResult.VALUE_MISMATCH);
        return results;
    }

    private Set<DnFilterCheckResult> checkDnFilterRelaxed(String dn, String filterValue, boolean autoBaseDn, String baseDN) {
        Set<DnFilterCheckResult> results = new HashSet<>();

        if (dn == null || filterValue == null || baseDN == null) {
            logger.debug("DN filter check failed: invalid input: dn={}, filterValue={}, baseDN={}", dn, filterValue, baseDN);
            results.add(DnFilterCheckResult.INVALID_INPUT);
            return results;
        }

        // Добавляем baseDN, если требуется
        String fullFilterValue = autoBaseDn && !filterValue.toLowerCase().contains("dc=") ? appendBaseDNIfMissing(filterValue, baseDN) : filterValue;
        String[] filterComponents = fullFilterValue.toLowerCase().split(",");
        String[] dnComponents = dn.toLowerCase().split(",");

        // Проверяем, что компоненты фильтра образуют непрерывную последовательность в DN
        for (int startIndex = 0; startIndex <= dnComponents.length - filterComponents.length; startIndex++) {
            boolean matched = true;
            for (int i = 0; i < filterComponents.length; i++) {
                int dnIndex = startIndex + i;
                if (dnIndex >= dnComponents.length) {
                    matched = false;
                    break;
                }

                String filterComponent = filterComponents[i];
                String dnComponent = dnComponents[dnIndex];

                if (!filterComponent.contains("=") || !dnComponent.contains("=")) {
                    logger.debug("DN filter check failed: invalid component format: filterComponent={}, dnComponent={}",
                            filterComponent, dnComponent);
                    results.add(DnFilterCheckResult.INVALID_COMPONENT_FORMAT);
                    matched = false;
                    break;
                }

                String[] filterParts = filterComponent.split("=", 2);
                String[] dnParts = dnComponent.split("=", 2);
                if (filterParts.length != 2 || dnParts.length != 2) {
                    logger.debug("DN filter check failed: invalid component structure: filterComponent={}, dnComponent={}",
                            filterComponent, dnComponent);
                    results.add(DnFilterCheckResult.INVALID_COMPONENT_FORMAT);
                    matched = false;
                    break;
                }

                String filterKey = filterParts[0].trim();
                String filterValuePart = filterParts[1].trim();
                String dnKey = dnParts[0].trim();
                String dnValue = dnParts[1].trim();

                logger.debug("Comparing components: filterKey={}, filterValue={}, dnKey={}, dnValue={}",
                        filterKey, filterValuePart, dnKey, dnValue);

                if (!filterKey.equals(dnKey)) {
                    matched = false;
                    break;
                }

                if (filterValuePart.equals("*")) {
                    continue;
                } else if (filterValuePart.contains("*")) {
                    String pattern = filterValuePart.replace("*", ".*");
                    if (!dnValue.matches(pattern)) {
                        logger.debug("DN filter check failed: value mismatch: dnValue={} does not match pattern={} in filter {}",
                                dnValue, pattern, filterComponent);
                        results.add(DnFilterCheckResult.VALUE_MISMATCH);
                        matched = false;
                        break;
                    }
                } else if (!filterValuePart.equals(dnValue)) {
                    logger.debug("DN filter check failed: value mismatch: filterValue={} != dnValue={} in components {} and {}",
                            filterValuePart, dnValue, filterComponent, dnComponent);
                    results.add(DnFilterCheckResult.VALUE_MISMATCH);
                    matched = false;
                    break;
                }
            }

            if (matched) {
                logger.debug("DN {} matches filter {} at startIndex {}", dn, fullFilterValue, startIndex);
                results.add(DnFilterCheckResult.MATCH);
                return results;
            }
        }

        if (results.isEmpty()) {
            logger.debug("DN {} does not match filter {}: no matching subsequence found", dn, fullFilterValue);
            results.add(DnFilterCheckResult.VALUE_MISMATCH);
        }

        return results;
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
    private FilterExtractionResult extractLocalFilters(Filter filter, List<LocalDnFilterCondition> localDnFilterConditions, String searchBaseDN) {
        List<ConfigProperties.TargetConfig.LocalDnFilter> localFilters = configProperties.getTargetConfig().getLocalDnFilters() != null ?
                configProperties.getTargetConfig().getLocalDnFilters() : Collections.emptyList();
        logger.debug("Local filters configured: {}", localFilters);

        if (localFilters.isEmpty()) {
            logger.debug("No local-dn-filters configured, returning original filter: {}", filter);
            return new FilterExtractionResult(localDnFilterConditions, filter, false);
        }

        if (filter.getFilterType() == Filter.FILTER_TYPE_AND || filter.getFilterType() == Filter.FILTER_TYPE_OR) {
            List<Filter> remainingComponents = new ArrayList<>();
            List<Filter> subComponents = new ArrayList<>(Arrays.asList(filter.getComponents()));
            DN_FILTER_TYPE conditionType = filter.getFilterType() == Filter.FILTER_TYPE_AND ? DN_FILTER_TYPE.AND : DN_FILTER_TYPE.OR;

            if (filter.getFilterType() == Filter.FILTER_TYPE_OR) {
                List<String> orValues = new ArrayList<>();
                String matchedAttribute = null;
                Boolean matchedAutoBaseDn = null;
                boolean allLocalFilters = true;
                List<Set<DnFilterValidationResult>> validationResultsList = new ArrayList<>();

                for (Filter subFilter : subComponents) {
                    if (subFilter.getFilterType() == Filter.FILTER_TYPE_EQUALITY) {
                        String attributeName = subFilter.getAttributeName();
                        Optional<ConfigProperties.TargetConfig.LocalDnFilter> matchedConfig = localFilters.stream()
                                .filter(config -> config.getAttribute().equalsIgnoreCase(attributeName))
                                .findFirst();
                        if (matchedConfig.isPresent()) {
                            String value = subFilter.getAssertionValue();
                            boolean autoBaseDn = matchedConfig.get().isAutoBaseDn();
                            Set<DnFilterValidationResult> validationResults = isValidDnFilter(value, autoBaseDn);
                            validationResultsList.add(validationResults);
                            if (!DnFilterValidationResult.isValidForEquality(validationResults)) {
                                logger.warn("Invalid DN filter for attribute {}: {}, reasons: {}, adding invalid condition",
                                        attributeName, value, DnFilterValidationResult.getValidationIssues(validationResults));
                                localDnFilterConditions.add(new LocalDnFilterCondition(DN_FILTER_TYPE.EQUALITY, attributeName, Collections.emptyList(), autoBaseDn, true));
                                return new FilterExtractionResult(localDnFilterConditions, Filter.createEqualityFilter("objectClass", "invalid"), true);
                            }
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
                        }
                    } else if (subFilter.getFilterType() == Filter.FILTER_TYPE_PRESENCE) {
                        String attributeName = subFilter.getAttributeName();
                        Optional<ConfigProperties.TargetConfig.LocalDnFilter> matchedConfig = localFilters.stream()
                                .filter(config -> config.getAttribute().equalsIgnoreCase(attributeName))
                                .findFirst();
                        if (matchedConfig.isPresent()) {
                            localDnFilterConditions.add(new LocalDnFilterCondition(DN_FILTER_TYPE.ANY, attributeName, Collections.singletonList("*"), matchedConfig.get().isAutoBaseDn()));
                            logger.debug("Extracted ANY local filter condition: filterType=DN, attribute={}", attributeName);
                        } else {
                            allLocalFilters = false;
                            remainingComponents.add(subFilter);
                        }
                    } else {
                        allLocalFilters = false;
                        remainingComponents.add(subFilter);
                    }
                }

                if (!orValues.isEmpty() && DnFilterValidationResult.isValidForOr(validationResultsList)) {
                    localDnFilterConditions.add(new LocalDnFilterCondition(DN_FILTER_TYPE.OR, matchedAttribute, orValues, matchedAutoBaseDn));
                    logger.debug("Extracted OR local filter condition: filterType=DN, attribute={}, autoBaseDn={}, values={}",
                            matchedAttribute, matchedAutoBaseDn, orValues);
                    if (allLocalFilters) {
                        return new FilterExtractionResult(localDnFilterConditions, null, false);
                    }
                } else if (!validationResultsList.isEmpty()) {
                    logger.warn("OR filter contains invalid subfilters, reasons: {}, adding invalid condition",
                            validationResultsList.stream()
                                    .map(DnFilterValidationResult::getValidationIssues)
                                    .collect(Collectors.joining("; ")));
                    localDnFilterConditions.add(new LocalDnFilterCondition(DN_FILTER_TYPE.OR, matchedAttribute, Collections.emptyList(), matchedAutoBaseDn != null && matchedAutoBaseDn, true));
                    return new FilterExtractionResult(localDnFilterConditions, Filter.createEqualityFilter("objectClass", "invalid"), true);
                }
            } else {
                for (Filter subFilter : subComponents) {
                    FilterExtractionResult subResult = extractLocalFilters(subFilter, localDnFilterConditions, searchBaseDN);
                    if (subResult.isRejectedDueToInvalidFilter()) {
                        localDnFilterConditions.add(new LocalDnFilterCondition(DN_FILTER_TYPE.AND, null, Collections.emptyList(), false, true));
                        return new FilterExtractionResult(localDnFilterConditions, Filter.createEqualityFilter("objectClass", "invalid"), true);
                    }
                    if (subResult.getRemainingFilter() != null) {
                        remainingComponents.add(subResult.getRemainingFilter());
                    }
                }
                if (!localDnFilterConditions.isEmpty() && conditionType.isLogicalOperator()) {
                    localDnFilterConditions.add(new LocalDnFilterCondition(DN_FILTER_TYPE.AND, null, Collections.emptyList(), false));
                    logger.debug("Extracted AND local filter condition: filterType=DN");
                }
            }

            if (remainingComponents.isEmpty()) {
                return new FilterExtractionResult(localDnFilterConditions, null, false);
            }

            if (filter.getFilterType() == Filter.FILTER_TYPE_AND) {
                return new FilterExtractionResult(localDnFilterConditions, Filter.createANDFilter(remainingComponents), false);
            } else {
                return new FilterExtractionResult(localDnFilterConditions, Filter.createORFilter(remainingComponents), false);
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
                    Set<DnFilterValidationResult> validationResults = isValidDnFilter(value, autoBaseDn);
                    if (!DnFilterValidationResult.isValidForNot(validationResults)) {
                        logger.warn("Invalid DN filter in NOT for attribute {}: {}, reasons: {}, adding invalid condition",
                                attributeName, value, DnFilterValidationResult.getValidationIssues(validationResults));
                        localDnFilterConditions.add(new LocalDnFilterCondition(DN_FILTER_TYPE.NOT, attributeName, Collections.emptyList(), autoBaseDn, true));
                        return new FilterExtractionResult(localDnFilterConditions, Filter.createEqualityFilter("objectClass", "invalid"), true);
                    }
                    if (autoBaseDn) {
                        value = appendBaseDNIfMissing(value, searchBaseDN);
                    }
                    localDnFilterConditions.add(new LocalDnFilterCondition(DN_FILTER_TYPE.NOT, attributeName, Collections.singletonList(value), autoBaseDn));
                    logger.debug("Extracted NOT local filter condition: filterType=DN, attribute={}, value={}", attributeName, value);
                    return new FilterExtractionResult(localDnFilterConditions, null, false);
                }
            }
            return new FilterExtractionResult(localDnFilterConditions, filter, false);
        } else if (filter.getFilterType() == Filter.FILTER_TYPE_EQUALITY) {
            String attributeName = filter.getAttributeName();
            Optional<ConfigProperties.TargetConfig.LocalDnFilter> matchedConfig = localFilters.stream()
                    .filter(config -> config.getAttribute().equalsIgnoreCase(attributeName))
                    .findFirst();
            if (matchedConfig.isPresent()) {
                String value = filter.getAssertionValue();
                boolean autoBaseDn = matchedConfig.get().isAutoBaseDn();
                Set<DnFilterValidationResult> validationResults = isValidDnFilter(value, autoBaseDn);
                if (!DnFilterValidationResult.isValidForEquality(validationResults)) {
                    logger.warn("Invalid DN filter for attribute {}: {}, reasons: {}, adding invalid condition",
                            attributeName, value, DnFilterValidationResult.getValidationIssues(validationResults));
                    localDnFilterConditions.add(new LocalDnFilterCondition(DN_FILTER_TYPE.EQUALITY, attributeName, Collections.emptyList(), autoBaseDn, true));
                    return new FilterExtractionResult(localDnFilterConditions, Filter.createEqualityFilter("objectClass", "invalid"), true);
                }
                if (autoBaseDn) {
                    value = appendBaseDNIfMissing(value, searchBaseDN);
                }
                localDnFilterConditions.add(new LocalDnFilterCondition(DN_FILTER_TYPE.EQUALITY, attributeName, Collections.singletonList(value), autoBaseDn));
                logger.debug("Extracted EQUALITY local filter condition: filterType=DN, attribute={}, value={}", attributeName, value);
                return new FilterExtractionResult(localDnFilterConditions, null, false);
            }
        } else if (filter.getFilterType() == Filter.FILTER_TYPE_PRESENCE) {
            String attributeName = filter.getAttributeName();
            Optional<ConfigProperties.TargetConfig.LocalDnFilter> matchedConfig = localFilters.stream()
                    .filter(config -> config.getAttribute().equalsIgnoreCase(attributeName))
                    .findFirst();
            if (matchedConfig.isPresent()) {
                localDnFilterConditions.add(new LocalDnFilterCondition(DN_FILTER_TYPE.ANY, attributeName, Collections.singletonList("*"), matchedConfig.get().isAutoBaseDn()));
                logger.debug("Extracted ANY local filter condition: filterType=DN, attribute={}", attributeName);
                return new FilterExtractionResult(localDnFilterConditions, null, false);
            }
        }

        return new FilterExtractionResult(localDnFilterConditions, filter, false);
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

    public Predicate<SearchResultEntry> getFilter(FilterExtractionResult extractionResult) {
        return entry -> {
            List<LocalDnFilterCondition> localDnFilterConditions = extractionResult.getConditions();
            if (localDnFilterConditions == null || localDnFilterConditions.isEmpty()) {
                if (extractionResult.isRejectedDueToInvalidFilter()) {
                    logger.debug("No local filter conditions due to invalid filter, rejecting entry DN: {}", entry.getDN());
                    return false;
                }
                logger.debug("No local filter conditions, passing entry DN: {}", entry.getDN());
                return true;
            }

            if (localDnFilterConditions.stream().anyMatch(LocalDnFilterCondition::isInvalid)) {
                logger.debug("Invalid filter condition detected, rejecting entry DN: {}", entry.getDN());
                return false;
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
                List<String> targetValues = new ArrayList<>();

                targetValues.add(entry.getDN().toLowerCase());
                if (attributeName.equals("distinguishedname")) {
                    Attribute attr = entry.getAttribute("distinguishedName");
                    if (attr != null) {
                        targetValues.addAll(Arrays.asList(attr.getValues()).stream()
                                .map(String::toLowerCase)
                                .collect(Collectors.toList()));
                    } else {
                        logger.debug("No distinguishedName attribute found, using DN: {}", entry.getDN());
                    }
                }

                logger.debug("Processing condition: type={}, attribute={}, values={}, targetValues={}",
                        condition.getType(), attributeName, condition.getValues(), targetValues);

                if (condition.getValues().isEmpty()) {
                    logger.warn("Empty values for condition type {}, attribute {}, rejecting condition",
                            condition.getType(), condition.getAttribute());
                    conditionMatch = false;
                } else {
                    switch (condition.getType()) {
                        case EQUALITY -> {
                            String value = condition.getValues().get(0).toLowerCase();
                            List<Set<DnFilterCheckResult>> resultsList = targetValues.stream()
                                    .map(target -> checkDnFilter(target, value, condition.isAutoBaseDn(), baseDN))
                                    .collect(Collectors.toList());
                            conditionMatch = resultsList.stream().anyMatch(DnFilterCheckResult::isMatch);
                            logger.debug("checkDnFilter for EQUALITY: value={}, results={}",
                                    value, resultsList.stream().map(DnFilterCheckResult::getCheckIssues).collect(Collectors.joining("; ")));
                        }
                        case ANY -> {
                            conditionMatch = !targetValues.isEmpty();
                            logger.debug("checkDnFilter for ANY: attribute={}, exists={}", attributeName, conditionMatch);
                        }
                        case OR -> {
                            List<Set<DnFilterCheckResult>> resultsList = new ArrayList<>();
                            for (String value : condition.getValues()) {
                                String finalValue = value.toLowerCase();
                                List<Set<DnFilterCheckResult>> subResults = targetValues.stream()
                                        .map(target -> checkDnFilter(target, finalValue, condition.isAutoBaseDn(), baseDN))
                                        .collect(Collectors.toList());
                                resultsList.addAll(subResults);
                            }
                            conditionMatch = resultsList.stream().anyMatch(DnFilterCheckResult::isMatch);
                            logger.debug("checkDnFilter for OR: values={}, results={}",
                                    condition.getValues(), resultsList.stream().map(DnFilterCheckResult::getCheckIssues).collect(Collectors.joining("; ")));
                        }
                        case AND -> {
                            List<Set<DnFilterCheckResult>> resultsList = new ArrayList<>();
                            for (String value : condition.getValues()) {
                                String finalValue = value.toLowerCase();
                                List<Set<DnFilterCheckResult>> subResults = targetValues.stream()
                                        .map(target -> checkDnFilter(target, finalValue, condition.isAutoBaseDn(), baseDN))
                                        .collect(Collectors.toList());
                                resultsList.addAll(subResults);
                            }
                            conditionMatch = resultsList.stream().allMatch(DnFilterCheckResult::isMatch);
                            logger.debug("checkDnFilter for AND: values={}, results={}",
                                    condition.getValues(), resultsList.stream().map(DnFilterCheckResult::getCheckIssues).collect(Collectors.joining("; ")));
                        }
                        case NOT -> {
                            String value = condition.getValues().get(0).toLowerCase();
                            List<Set<DnFilterCheckResult>> resultsList = targetValues.stream()
                                    .map(target -> checkDnFilter(target, value, condition.isAutoBaseDn(), baseDN))
                                    .collect(Collectors.toList());
                            conditionMatch = !resultsList.stream().anyMatch(DnFilterCheckResult::isMatch);
                            logger.debug("checkDnFilter for NOT: value={}, results={}",
                                    value, resultsList.stream().map(DnFilterCheckResult::getCheckIssues).collect(Collectors.joining("; ")));
                        }
                        default -> {
                            logger.warn("Unsupported condition type: {}", condition.getType());
                            conditionMatch = false;
                        }
                    }
                }

                if (condition.getType() == DN_FILTER_TYPE.OR) {
                    matches |= conditionMatch; // OR: хотя бы одно условие должно совпасть
                } else {
                    matches &= conditionMatch; // AND, EQUALITY, NOT: все условия должны совпасть
                }

                if (!matches && condition.getType() == DN_FILTER_TYPE.AND) {
                    break; // Ранний выход для AND
                }
            }

            logger.debug("Entry DN {} local filter conditions: {}", entry.getDN(), matches ? "matches" : "does not match");
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
        FilterExtractionResult extractionResult;
        try {
            extractionResult = extractLocalFilters(originalFilter, localDnFilterConditions, searchBaseDN);
        } catch (Exception e) {
            logger.warn("Error in extractLocalFilters, rejecting filter: {}", originalFilter, e);
            return new FilterResult(Filter.createEqualityFilter("objectClass", "invalid"), Collections.emptyList(), localDnFilterConditions);
        }
        logger.debug("extractLocalFilters took {} ms", System.currentTimeMillis() - step3Start);
        Filter transformedFilter = extractionResult.getRemainingFilter();
        if (transformedFilter == null) {
            transformedFilter = Filter.createPresenceFilter("objectClass");
            logger.debug("All filters extracted for local filtering, using (objectClass=*) for server query");
        } else if (extractionResult.isRejectedDueToInvalidFilter()) {
            transformedFilter = Filter.createEqualityFilter("objectClass", "invalid");
            logger.debug("Invalid filter detected, setting transformed filter to (objectClass=invalid)");
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

}
