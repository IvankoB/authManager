package edu.uwed.authManager.ldap;

import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.SearchResultEntryProtocolOp;
import com.unboundid.ldap.sdk.*;
import edu.uwed.authManager.configuration.ConfigProperties;
import io.netty.channel.ChannelHandlerContext;
import io.netty.util.AttributeKey;
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
public class LdapSearchMITM {
    private static final Logger logger = LoggerFactory.getLogger(LdapSearchMITM.class);
    private final ConfigProperties configProperties;

    @Autowired
    public LdapSearchMITM(ConfigProperties configProperties) {
        this.configProperties = configProperties;
    }

    // Генерация серверного LDAP-фильтра с заменой локальных атрибутов
    public Filter generateLdapFilter(Filter originalFilter, ChannelHandlerContext ctx) {
        List<ConfigProperties.LocalAttribute> attributes = configProperties.getTargetConfig().getLocalAttributes();

        // Проверка домена на этапе фильтрации
        Filter modifiedFilter = checkDomainInFilter(originalFilter, attributes);
        if (modifiedFilter != null) {
            return modifiedFilter; // Если домен недопустим, возвращаем фильтр, который не даст результатов
        }

        // Сохраняем значение фильтра для использования в обработке результатов
        String filterValue = extractValueFromFilter(originalFilter);
        if (filterValue != null && ctx != null) {
            ctx.channel().attr(AttributeKey.valueOf("filterValue")).set(filterValue);
            logger.debug("Extracted filter value: {}", filterValue);
        }

        return replaceLocalAttributes(originalFilter, attributes);
    }

    // Рекурсивная замена локальных атрибутов на серверные, сохраняя структуру фильтра
    private Filter replaceLocalAttributes(Filter filter, List<ConfigProperties.LocalAttribute> attributes) {
        if (filter.getFilterType() == Filter.FILTER_TYPE_EQUALITY) {
            String attributeName = filter.getAttributeName();
            // Проверяем, является ли атрибут локальным
            ConfigProperties.LocalAttribute matchingAttr = attributes.stream()
                    .filter(attr -> attr.getName().equalsIgnoreCase(attributeName))
                    .findFirst()
                    .orElse(null);

            if (matchingAttr != null && matchingAttr.getSearchExpression() != null) {
                // Локальный атрибут, заменяем на серверный фильтр
                String username = extractUsernameFromValue(filter.getAssertionValue());
                if (username != null && !username.isEmpty()) {
                    String targetAttribute = extractAttributeName(matchingAttr.getSearchExpression());
                    // Форматируем значение серверного фильтра с учётом searchExpression
                    String targetValue = formatServerFilterValue(matchingAttr.getSearchExpression(), username);
                    logger.debug("Replacing local attribute '{}' with server filter for '{}={}'", attributeName, targetAttribute, targetValue);
                    return Filter.createEqualityFilter(targetAttribute, targetValue);
                } else {
                    logger.debug("No valid username found in client filter for '{}', using presence filter for 'mail'", attributeName);
                    return Filter.createPresenceFilter("mail");
                }
            }
            // Не локальный атрибут, возвращаем без изменений
            return filter;
        } else if (filter.getFilterType() == Filter.FILTER_TYPE_AND || filter.getFilterType() == Filter.FILTER_TYPE_OR) {
            // Рекурсивно обрабатываем дочерние фильтры
            List<Filter> modifiedFilters = new ArrayList<>();
            for (Filter subFilter : filter.getComponents()) {
                Filter modifiedSubFilter = replaceLocalAttributes(subFilter, attributes);
                modifiedFilters.add(modifiedSubFilter);
            }
            // Создаем новый фильтр с той же логикой (AND или OR)
            return filter.getFilterType() == Filter.FILTER_TYPE_AND
                    ? Filter.createANDFilter(modifiedFilters)
                    : Filter.createORFilter(modifiedFilters);
        }
        // Другие типы фильтров (например, presence, substring) оставляем без изменений
        return filter;
    }

    // Метод для проверки домена в фильтре с учётом атрибутов
    private Filter checkDomainInFilter(Filter filter, List<ConfigProperties.LocalAttribute> attributes) {
        ConfigProperties.TargetConfig targetConfig = configProperties.getTargetConfig();
        String targetDomain = targetConfig.getDomain();
        List<String> localDomains = targetConfig.getLocalDomains();

        if (filter.getFilterType() == Filter.FILTER_TYPE_EQUALITY) {
            String attributeName = filter.getAttributeName();
            // Проверяем, есть ли атрибут в конфигурации и включён ли флаг local-domains-only
            Optional<ConfigProperties.LocalAttribute> matchingAttr = attributes.stream()
                    .filter(attr -> attr.getName().equalsIgnoreCase(attributeName) && attr.isLocalDomainsOnly())
                    .findFirst();

            if (matchingAttr.isPresent()) {
                String email = filter.getAssertionValue();
                if (!isDomainAllowed(email, targetDomain, localDomains)) {
                    logger.warn("Search rejected: email '{}' for attribute '{}' has a domain not in allowed list (target: {}, local: {})",
                            email, attributeName, targetDomain, localDomains);
                    // Возвращаем фильтр, который не даст результатов
                    return Filter.createEqualityFilter("objectClass", "invalid");
                }
            }
        } else if (filter.getFilterType() == Filter.FILTER_TYPE_AND ||
                filter.getFilterType() == Filter.FILTER_TYPE_OR) {
            // Рекурсивно проверяем дочерние фильтры
            for (Filter subFilter : filter.getComponents()) {
                Filter result = checkDomainInFilter(subFilter, attributes);
                if (result != null) {
                    return result; // Если хотя бы один фильтр отклонён, прерываем поиск
                }
            }
        }
        return null; // Домен допустим или фильтр не подпадает под проверку
    }

    // Извлечение значения фильтра (например, ivano@uwed.ac.uz из postalAddress=ivano@uwed.ac.uz)
    private String extractValueFromFilter(Filter filter) {
        if (filter.getFilterType() == Filter.FILTER_TYPE_EQUALITY) {
            String attributeName = filter.getAttributeName();
            if ("postalAddress".equalsIgnoreCase(attributeName)) {
                return filter.getAssertionValue();
            }
        } else if (filter.getFilterType() == Filter.FILTER_TYPE_AND || filter.getFilterType() == Filter.FILTER_TYPE_OR) {
            for (Filter subFilter : filter.getComponents()) {
                String value = extractValueFromFilter(subFilter);
                if (value != null) {
                    return value;
                }
            }
        }
        return null;
    }

    // Извлечение username из значения фильтра (например, ivano@uwed.ac.uz -> ivano)
    private String extractUsernameFromValue(String value) {
        if (value != null && value.contains("@")) {
            String username = value.split("@")[0];
            if (!username.isEmpty()) {
                return username;
            }
        }
        return null;
    }

    // Форматирование значения серверного фильтра на основе searchExpression
    private String formatServerFilterValue(String searchExpression, String username) {
        if (searchExpression.contains("[[email:username]]")) {
            // Заменяем [[email:username]] на username
            String result = searchExpression.replace("[[email:username]]", username);
            // Удаляем часть {{userPrincipalName}}=, оставляя только значение
            Pattern pattern = Pattern.compile("\\{\\{[^}]+\\}\\}=");
            Matcher matcher = pattern.matcher(result);
            if (matcher.find()) {
                return matcher.replaceFirst("");
            }
            return result;
        }
        return username;
    }

    // Извлечение имени атрибута из выражения (например, {{userPrincipalName}} -> userPrincipalName)
    private String extractAttributeName(String expression) {
        Pattern pattern = Pattern.compile("\\{\\{([^}]+)\\}\\}");
        Matcher matcher = pattern.matcher(expression);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return "";
    }

    // Извлечение зависимых атрибутов из result-expression
    private Set<String> extractAttributesFromExpression(String resultExpression) {
        Set<String> attributes = new HashSet<>();
        if (resultExpression == null) {
            return attributes;
        }

        // Ищем все вхождения {{attribute}}
        Pattern pattern = Pattern.compile("\\{\\{([^{}]+)\\}\\}");
        Matcher matcher = pattern.matcher(resultExpression);
        while (matcher.find()) {
            String attr = matcher.group(1).trim();
            attributes.add(attr);
            logger.debug("Extracted dependent attribute from result-expression: {}", attr);
        }
        return attributes;
    }

    // Проверка, является ли строка email и извлечение username
    private String extractUsernameFromEmail(String email) {
        if (email != null && email.contains("@")) {
            String[] parts = email.split("@");
            if (parts.length == 2 && !parts[0].isEmpty() && !parts[1].isEmpty()) {
                return parts[0]; // username
            }
        }
        return null;
    }

    // Проверка, входит ли домен в список разрешённых доменов
    private boolean isDomainAllowed(String email, String targetDomain, List<String> localDomains) {
        if (email == null || !email.contains("@")) {
            return false;
        }
        String domain = email.split("@")[1];
        return domain.equalsIgnoreCase(targetDomain) || localDomains.stream()
                .anyMatch(allowedDomain -> domain.equalsIgnoreCase(allowedDomain));
    }

    // Проверка, является ли строка DN (грубая проверка на наличие "dc=" или "cn=")
    private boolean isDnFormat(String bindDn) {
        return bindDn != null && (bindDn.toLowerCase().contains("dc=") || bindDn.toLowerCase().contains("cn="));
    }

    // Обработка bindDN для BindRequest
    public String processBindExpression(String dn, String password, LDAPConnection conn) throws LDAPException {
        ConfigProperties.TargetConfig targetConfig = configProperties.getTargetConfig();

        // Если bindDN в формате DN (например, cn=ivan ivanovich,ou=it,dc=uwed,dc=edu), оставляем без изменений
        if (isDnFormat(dn)) {
            logger.debug("bindDN '{}' is in DN format, using as is", dn);
            return dn;
        }

        // Проверяем, включено ли map-local-domains и является ли dn email
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
                    return null; // Домен не разрешён, возвращаем null
                }
            }
        }

        // Если dn не в формате email и map-local-domains не применимо, возвращаем исходный dn
        logger.debug("No mapping applied, using original bindDN: {}", dn);
        return dn;
    }

    // Фильтр для клиентской фильтрации (временно отключен, пропускает все записи)
    public Predicate<SearchResultEntry> getFilter() {
        return entry -> {
            logger.debug("Client-side filtering is disabled, passing entry DN: {}", entry.getDN());
            return true;
        };
    }

    // Обработчик для модификации результатов поиска
    public BiFunction<SearchResultEntry, Integer, LDAPMessage> getEntryProcessor(ChannelHandlerContext ctx, List<String> requestedAttributes) {
        return (entry, msgID) -> {
            Map<String, Attribute> updatedAttributes = entry.getAttributes().stream().collect(Collectors.toMap(
                    Attribute::getName, attr -> attr, (attr1, attr2) -> attr1, HashMap::new));

            List<ConfigProperties.LocalAttribute> attributes = configProperties.getTargetConfig().getLocalAttributes();
            Set<String> dependentAttributes = new HashSet<>();

            // Собираем все зависимые атрибуты из result-expression
            for (ConfigProperties.LocalAttribute attr : attributes) {
                String resultExpression = attr.getResultExpression();
                if (resultExpression != null) {
                    dependentAttributes.addAll(extractAttributesFromExpression(resultExpression));
                }
            }

            // Формируем локальные атрибуты на основе result-expression
            for (ConfigProperties.LocalAttribute attr : attributes) {
                String resultExpression = attr.getResultExpression();
                if (resultExpression != null && !resultExpression.isEmpty()) {
                    // Передаём сам attr, чтобы знать, включена ли опция local-domains-only
                    String value = parseResultExpression(entry, resultExpression, ctx, attr);
                    if (value != null) {
                        updatedAttributes.put(attr.getName(), new Attribute(attr.getName(), value));
                        logger.debug("Set attribute {} to {} for entry DN: {}", attr.getName(), value, entry.getDN());
                    }
                }
            }

            // Удаляем зависимые атрибуты, если они не запрошены клиентом или не разрешены
            Iterator<Map.Entry<String, Attribute>> iterator = updatedAttributes.entrySet().iterator();
            while (iterator.hasNext()) {
                Map.Entry<String, Attribute> attrEntry = iterator.next();
                String attrName = attrEntry.getKey();
                boolean isDependent = dependentAttributes.stream().anyMatch(depAttr -> depAttr.equalsIgnoreCase(attrName));
                boolean isRequested = requestedAttributes.stream().anyMatch(reqAttr -> reqAttr.equalsIgnoreCase(attrName));
                boolean isGenerated = attributes.stream().anyMatch(localAttr -> localAttr.getName().equalsIgnoreCase(attrName));

                // Проверяем, разрешено ли оставлять зависимые атрибуты
                boolean allowDependentAttributes = attributes.stream()
                        .filter(localAttr -> localAttr.getName().equalsIgnoreCase(attrName))
                        .findFirst()
                        .map(ConfigProperties.LocalAttribute::isDependentAttributes)
                        .orElse(false);

                if (isDependent && !isRequested && !isGenerated && !allowDependentAttributes) {
                    logger.debug("Removing dependent attribute {} as it was not requested by client and dependent-attributes=false", attrName);
                    iterator.remove();
                }
            }

            List<Attribute> updatedAttributesList = new ArrayList<>(updatedAttributes.values());
            Entry updatedEntry = new Entry(entry.getDN(), updatedAttributesList);
            SearchResultEntry updatedSearchResultEntry = new SearchResultEntry(updatedEntry);
            SearchResultEntryProtocolOp entryOp = new SearchResultEntryProtocolOp(updatedSearchResultEntry);
            return new LDAPMessage(msgID, entryOp);
        };
    }


    // Парсинг result-expression с учётом нескольких атрибутов
    private String parseResultExpression(SearchResultEntry entry, String expression, ChannelHandlerContext ctx, ConfigProperties.LocalAttribute localAttr) {
        String newValue = expression;
        Set<String> dependentAttrs = extractAttributesFromExpression(expression);
        for (String depAttr : dependentAttrs) {
            String placeholder = "{{" + depAttr + "}}";
            String replacement = entry.getAttributeValue(depAttr);
            if (replacement == null) {
                // Если атрибут не вернулся с сервера, используем запасное значение
                String filterValue = (String) ctx.channel().attr(AttributeKey.valueOf("filterValue")).get();
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

        // Проверяем домен в результате, только если local-domains-only=true
        if (localAttr.isLocalDomainsOnly() && newValue.contains("@")) {
            String domain = newValue.substring(newValue.indexOf("@") + 1);
            ConfigProperties.TargetConfig targetConfig = configProperties.getTargetConfig();
            String targetDomain = targetConfig.getDomain();
            List<String> localDomains = targetConfig.getLocalDomains() != null ? targetConfig.getLocalDomains() : Collections.emptyList();

            // Проверяем, совпадает ли домен с target.domain или одним из local-domains
            boolean isDomainAllowed = domain.equalsIgnoreCase(targetDomain) ||
                    localDomains.stream().anyMatch(allowedDomain -> domain.equalsIgnoreCase(allowedDomain));
            if (!isDomainAllowed) {
                logger.warn("Invalid domain in result for attribute {}: {}. Expected target domain: {}, local domains: {}",
                        localAttr.getName(), domain, targetDomain, localDomains);
                return null;
            }
        }
        return newValue;
    }

//    //////////// Создаем предикат для фильтрации
//    public static Predicate<SearchResultEntry> filter = entry -> {
//        String mail = entry.getAttributeValue("mail");
//        String cn = entry.getAttributeValue("cn");
//        return true;
//        //return (mail != null && mail.contains("@example.com")) &&
//    };
//
//    //////////// Создаем функцию-обработчик для модификации записи
//    public static BiFunction<SearchResultEntry, Integer, LDAPMessage> entryProcessor = (entry, msgID) -> {
//        // Извлекаем текущие атрибуты записи в Map
//        Map<String, Attribute> updatedAttributes = entry.getAttributes().stream()
//                .collect(Collectors.toMap(
//                        Attribute::getName,
//                        attr -> attr,
//                        (attr1, attr2) -> attr1, // В случае дубликатов берем первый атрибут
//                        HashMap::new
//                ));
//
//        //// Пример модификации атрибутов:
//        //// 1. Удаляем атрибут cn
//        //updatedAttributes.removeIf(attr -> attr.getName().equals("cn"));
//
//        //// 2. Изменяем атрибут mail
//        //updatedAttributes.removeIf(attr -> attr.getName().equals("mail"));
//        //updatedAttributes.add(new Attribute("mail", "newemail@example.com"));
//
//        //// 3. Добавляем новый атрибут telephoneNumber
//        //updatedAttributes.add(new Attribute("telephoneNumber", "+1234567890"));
//
//        updatedAttributes.put(
//                "registeredAddress",
//                new Attribute("registeredAddress", updatedAttributes.get("sAMAccountName").getValue() + "@uwed.uz")
//        );
//        updatedAttributes.put(
//                "postalAddress",
//                new Attribute("postalAddress", updatedAttributes.get("sAMAccountName").getValue() + "@uwed.ac.uz")
//        );
//
//        // Преобразуем Map обратно в List для создания Entry
//        List<Attribute> updatedAttributesList = new ArrayList<>(updatedAttributes.values());
//        // Создаем новый Entry с обновленными атрибутами
//        Entry updatedEntry = new Entry(entry.getDN(), updatedAttributesList);
//        // Преобразуем обновленный Entry в SearchResultEntry
//        SearchResultEntry updatedSearchResultEntry = new SearchResultEntry(updatedEntry);
//        // Преобразуем SearchResultEntry в SearchResultEntryProtocolOp
//        SearchResultEntryProtocolOp entryOp = new SearchResultEntryProtocolOp(updatedSearchResultEntry);
//        // Создаем LDAPMessage с переданным messageID
//        return new LDAPMessage(msgID, entryOp);
//    };

}
