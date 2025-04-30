package edu.uwed.authManager.ldap;

import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.SearchResultEntryProtocolOp;
import com.unboundid.ldap.sdk.*;
import edu.uwed.authManager.configuration.ConfigProperties;
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

@Component
public class LdapMITM {
    private static final Logger logger = LoggerFactory.getLogger(LdapMITM.class);
    private final ConfigProperties configProperties;

    @Data
    public static class LocalFilterCondition {
        private final String type;        // "SIMPLE", "OR", "AND", "NOT"
        private final LdapConstants.FILTER_TYPE filterType;  // Используем перечисление из LdapConstants
        private final String attribute;   // Например, "distinguishedName"
        private final List<String> values; // Для SIMPLE — одно значение, для OR — список значений
        private final boolean autoBaseDn; // Нужно ли добавлять baseDN
    }

    @Data
    public static class FilterResult {
        private final Filter filter;
        private final String filterValue;
//        private final List<LocalFilterCondition> localFilterConditions; // Добавляем условия в результат
    }

    @Autowired
    public LdapMITM(ConfigProperties configProperties) {
        this.configProperties = configProperties;
    }

    public FilterResult generateLdapFilterOLD(Filter originalFilter) {
        List<ConfigProperties.LocalAttribute> attributes = configProperties.getTargetConfig().getLocalAttributes();

        Filter modifiedFilter = checkDomainInFilter(originalFilter, attributes);
        if (modifiedFilter != null) {
            return new FilterResult(modifiedFilter, null);
        }

        String filterValue = extractValueFromFilter(originalFilter);
        if (filterValue != null) {
            logger.debug("Extracted filter value: {}", filterValue);
        }

        Filter finalFilter = replaceLocalAttributes(originalFilter, attributes);
        return new FilterResult(finalFilter, filterValue);
    }

    public FilterResult generateLdapFilter(Filter originalFilter) {
        List<ConfigProperties.LocalAttribute> attributes = configProperties.getTargetConfig().getLocalAttributes();

        // Проверяем домен в фильтре
        Filter modifiedFilter = checkDomainInFilter(originalFilter, attributes);
        if (modifiedFilter != null) {
            return new FilterResult(modifiedFilter, null);
        }

        String filterValue = extractValueFromFilter(originalFilter);
        if (filterValue != null) {
            logger.debug("Extracted filter value: {}", filterValue);
        }

        // Рекурсивно обрабатываем фильтр
        Filter finalFilter = transformPresenceFilters(originalFilter, attributes);
        return new FilterResult(finalFilter, filterValue);
    }

    // Новый метод для рекурсивной обработки фильтров
    private Filter transformPresenceFilters(Filter filter, List<ConfigProperties.LocalAttribute> attributes) {
        // Если фильтр — это PRESENCE
        if (filter.getFilterType() == Filter.FILTER_TYPE_PRESENCE) {
            String attributeName = filter.getAttributeName();
            ConfigProperties.LocalAttribute matchingAttr = attributes.stream()
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


    private Filter replaceLocalAttributes(Filter filter, List<ConfigProperties.LocalAttribute> attributes) {
        if (filter.getFilterType() == Filter.FILTER_TYPE_EQUALITY) {
            String attributeName = filter.getAttributeName();
            ConfigProperties.LocalAttribute matchingAttr = attributes.stream()
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
        }
        return filter;
    }

    private Filter checkDomainInFilter(Filter filter, List<ConfigProperties.LocalAttribute> attributes) {
        ConfigProperties.TargetConfig targetConfig = configProperties.getTargetConfig();
        String targetDomain = targetConfig.getDomain();
        List<String> localDomains = targetConfig.getLocalDomains();

        if (filter.getFilterType() == Filter.FILTER_TYPE_EQUALITY) {
            String attributeName = filter.getAttributeName();
            Optional<ConfigProperties.LocalAttribute> matchingAttr = attributes.stream()
                    .filter(attr -> attr.getName().equalsIgnoreCase(attributeName) && attr.isLocalDomainsOnly())
                    .findFirst();

            if (matchingAttr.isPresent()) {
                String email = filter.getAssertionValue();
                if (!isDomainAllowed(email, targetDomain, localDomains)) {
                    logger.warn("Search rejected: email '{}' for attribute '{}' has a domain not in allowed list (target: {}, local: {})",
                            email, attributeName, targetDomain, localDomains);
                    return Filter.createEqualityFilter("objectClass", "invalid");
                }
            }
        } else
        if (
            filter.getFilterType() == Filter.FILTER_TYPE_AND
            ||
            filter.getFilterType() == Filter.FILTER_TYPE_OR
        ) {
            for (Filter subFilter : filter.getComponents()) {
                Filter result = checkDomainInFilter(subFilter, attributes);
                if (result != null) {
                    return result;
                }
            }
        }
        return null;
    }

    private String extractValueFromFilter(Filter filter) {
        if (filter.getFilterType() == Filter.FILTER_TYPE_EQUALITY) {
            String attributeName = filter.getAttributeName();
            if ("postalAddress".equalsIgnoreCase(attributeName)) {
                return filter.getAssertionValue();
            }
        } else
        if (filter.getFilterType() == Filter.FILTER_TYPE_AND || filter.getFilterType() == Filter.FILTER_TYPE_OR) {
            for (Filter subFilter : filter.getComponents()) {
                String value = extractValueFromFilter(subFilter);
                if (value != null) {
                    return value;
                }
            }
        }
        return null;
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

    public Predicate<SearchResultEntry> getFilter() {
        return entry -> {
            logger.debug("Client-side filtering is disabled, passing entry DN: {}", entry.getDN());
            return true;
        };
    }

    // в каждой из вовзращенных сервером записей вычислям локальные атрибуты по значениям серверным
    public BiFunction<SearchResultEntry, Integer, LDAPMessage> getEntryProcessor(List<String> requestedAttributes, String filterValue) {
        return (entry, messageId) -> {
            // 1. Собираем зависимые атрибуты из resultExpression
            Set<String> dependentAttributes = configProperties.getTargetConfig().getLocalAttributes().stream()
                    .map(ConfigProperties.LocalAttribute::getResultExpression)
                    .filter(Objects::nonNull)
                    .flatMap(expr -> extractAttributesFromExpression(expr).stream())
                    .collect(Collectors.toSet());
            logger.debug("Dependent attributes: {}", dependentAttributes);

            // 2. Создаем список атрибутов для новой записи
            List<Attribute> attributes = new ArrayList<>();

            // 3. Обработка серверных атрибутов
            boolean returnAllAttributes = requestedAttributes == null ||
                    requestedAttributes.isEmpty() ||
                    requestedAttributes.contains("*");
            if (returnAllAttributes) {
                // Добавляем все серверные атрибуты
                for (Attribute attr : entry.getAttributes()) {
                    attributes.add(attr);
                }
                logger.debug("Returning all server attributes for clientMessageId: {}, DN: {}, requested: {}",
                        messageId, entry.getDN(), requestedAttributes);
            } else {
                // Добавляем только запрошенные атрибуты
                for (String attr : requestedAttributes) {
                    Attribute serverAttr = entry.getAttribute(attr);
                    if (serverAttr != null) {
                        attributes.add(serverAttr);
                    }
                }
                logger.debug("Returning requested attributes for clientMessageId: {}, DN: {}, attributes: {}",
                        messageId, entry.getDN(), requestedAttributes);
            }

            // 4. Добавление локальных атрибутов
            for (ConfigProperties.LocalAttribute localAttr : configProperties.getTargetConfig().getLocalAttributes()) {
                String resultExpression = localAttr.getResultExpression();
                if (resultExpression != null) {
                    String value = evaluateExpression(resultExpression, entry);
                    if (value != null) {
                        attributes.add(new Attribute(localAttr.getName(), value));
                        logger.debug("Added local attribute {}={} for clientMessageId: {}",
                                localAttr.getName(), value, messageId);
                    }
                }
            }

            // 5. Фильтрация зависимых атрибутов, если не запрошены
            if (!returnAllAttributes) {
                attributes = attributes.stream()
                        .filter(attr -> {
                            boolean isDependent = dependentAttributes.stream()
                                    .anyMatch(depAttr -> depAttr.equalsIgnoreCase(attr.getName()));
                            boolean isRequested = requestedAttributes.stream()
                                    .anyMatch(reqAttr -> reqAttr.equalsIgnoreCase(attr.getName()));
                            boolean isLocal = configProperties.getTargetConfig().getLocalAttributes().stream()
                                    .anyMatch(localAttr -> localAttr.getName().equalsIgnoreCase(attr.getName()));
                            // Сохраняем атрибут, если он запрошен, является локальным или не зависимый
                            return isRequested || isLocal || !isDependent;
                        })
                        .collect(Collectors.toList());
                logger.debug("Filtered attributes for clientMessageId: {}, remaining attributes: {}",
                        messageId, attributes.stream().map(Attribute::getName).collect(Collectors.toList()));
            }

            // 6. Создаем новый Entry
            Entry updatedEntry = new Entry(entry.getDN(), attributes);
            SearchResultEntry updatedSearchResultEntry = new SearchResultEntry(updatedEntry);

            // 7. Формируем LDAPMessage
            SearchResultEntryProtocolOp entryOp = new SearchResultEntryProtocolOp(updatedSearchResultEntry);
            return new LDAPMessage(messageId, entryOp);
        };
    }

    private String parseResultExpression(SearchResultEntry entry, String expression, String filterValue, ConfigProperties.LocalAttribute localAttr) {
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

    // Новая stateless-функция
    public List<String> enhanceRequestedAttributes(List<String> requestedAttributes) {
        List<String> attributesToRequest = new ArrayList<>();

        if (requestedAttributes == null || requestedAttributes.isEmpty() || requestedAttributes.contains("*")) {
            attributesToRequest.add("*");
            logger.debug("Client requested '*' or no attributes, adding '*' to request all server attributes");
        } else {
            attributesToRequest.addAll(requestedAttributes);
            logger.debug("Requested attributes by client: {}", requestedAttributes);

            // Добавляем зависимые атрибуты для локальных вычислений
            for (ConfigProperties.LocalAttribute attr : configProperties.getTargetConfig().getLocalAttributes()) {
                Set<String> attrNames = extractAttributeNames(attr.getResultExpression());
                for (String depAttr : attrNames) {
                    if (!attributesToRequest.contains(depAttr) && !depAttr.equals("*")) {
                        attributesToRequest.add(depAttr);
                        logger.debug("Added dependent attribute to request: {}", depAttr);
                    }
                }
            }
        }
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

    private String evaluateExpression(String resultExpression, SearchResultEntry entry) {
        if (resultExpression == null || entry == null) {
            return null;
        }

        try {
            String result = resultExpression;
            Set<String> attrNames = extractAttributeNames(resultExpression);
            for (String attrName : attrNames) {
                Attribute attr = entry.getAttribute(attrName);
                String value = (attr != null && attr.getValues().length > 0) ? attr.getValues()[0] : "";
                result = result.replace("{{" + attrName + "}}", value);
            }

            logger.debug("Evaluated expression {} to value: {}", resultExpression, result);
            return result.isEmpty() ? null : result;
        } catch (Exception e) {
            logger.error("Failed to evaluate expression: {}, error: {}", resultExpression, e.getMessage());
            return null;
        }
    }

}
