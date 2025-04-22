package edu.uwed.authManager.ldap;

import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.SearchResultEntryProtocolOp;
import com.unboundid.ldap.sdk.*;
import edu.uwed.authManager.configuration.ConfigProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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
    public Filter generateLdapFilter(Filter originalFilter) {
        List<ConfigProperties.LocalAttribute> attributes = configProperties.getTargetConfig().getLocalAttributes();
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

    // Извлечение имени атрибута
    private String extractAttributeName(String expression) {
        Pattern pattern = Pattern.compile("\\{\\{([^}]+)\\}\\}");
        Matcher matcher = pattern.matcher(expression);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return "";
    }

    // Извлечение username из DN (например, cn=ivan ivanovich -> ivan)
    private String extractUsernameFromDn(String dn) {
        if (dn != null) {
            Pattern pattern = Pattern.compile("cn=([^,]+)", Pattern.CASE_INSENSITIVE);
            Matcher matcher = pattern.matcher(dn);
            if (matcher.find()) {
                String cn = matcher.group(1);
                // Предполагаем, что username — это первая часть CN (до пробела, если есть)
                return cn.contains(" ") ? cn.split(" ")[0] : cn;
            }
        }
        return null;
    }

    // Извлечение username с использованием поиска (если DN не содержит нужных данных)
    private String extractUsernameFromDnOrSearch(String dn, LDAPConnection conn) throws LDAPException {
        String username = extractUsernameFromDn(dn);
        if (username != null && !username.isEmpty()) {
            return username;
        }

        // Если не удалось извлечь username из DN, выполняем поиск
        SearchRequest searchRequest = new SearchRequest(
                dn, SearchScope.BASE, Filter.createEqualityFilter("objectClass", "person"), "sAMAccountName"
        );
        SearchResultEntry entry = conn.searchForEntry(searchRequest);
        if (entry != null) {
            return entry.getAttributeValue("sAMAccountName");
        }
        return null;
    }

    // Форматирование bindExpression (например, {{userPrincipalName}}=[[email:username]]@uwed.edu -> ivan@uwed.edu)
    private String formatBindExpression(String bindExpression, String username) {
        if (bindExpression.contains("[[email:username]]")) {
            // Заменяем [[email:username]] на username
            String result = bindExpression.replace("[[email:username]]", username);
            // Удаляем часть {{userPrincipalName}}, оставляя только значение
            Pattern pattern = Pattern.compile("\\{\\{[^}]+\\}\\}=");
            Matcher matcher = pattern.matcher(result);
            if (matcher.find()) {
                return matcher.replaceFirst("");
            }
            return result;
        }
        return username;
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

        // Используем старую логику с bindExpression, если map-local-domains не применимо
        List<ConfigProperties.LocalAttribute> attributes = configProperties.getTargetConfig().getLocalAttributes();
        for (ConfigProperties.LocalAttribute attr : attributes) {
            String bindExpression = attr.getBindExpression();
            if (bindExpression != null && !bindExpression.trim().isEmpty()) {
                String username = extractUsernameFromDnOrSearch(dn, conn);
                if (username != null) {
                    String bindValue = formatBindExpression(bindExpression, username);
                    logger.debug("Processed bind expression '{}' for DN '{}': {}", bindExpression, dn, bindValue);
                    return bindValue;
                }
            }
        }

        // Если ни одна логика не применима, возвращаем исходный dn
        logger.debug("No mapping or bind expression applied, using original bindDN: {}", dn);
        return dn;
    }

    // Фильтр для клиентской фильтрации (временно отключен, пропускает все записи)
    public Predicate<SearchResultEntry> getFilter() {
        return entry -> {
            // Клиентская фильтрация пока не требуется, пропускаем все записи
            // Задел для будущей локальной фильтрации по DN-атрибутам (например, OU)
            // TODO: Добавить локальную фильтрацию, когда будут определены настройки
            logger.debug("Client-side filtering is disabled, passing entry DN: {}", entry.getDN());
            return true;
        };
    }

    // Обработчик для модификации результатов поиска
    public BiFunction<SearchResultEntry, Integer, LDAPMessage> getEntryProcessor() {
        return (entry, msgID) -> {
            Map<String, Attribute> updatedAttributes = entry.getAttributes().stream().collect(Collectors.toMap(
                    Attribute::getName, attr -> attr,(attr1, attr2) -> attr1,HashMap::new));

            List<ConfigProperties.LocalAttribute> attributes = configProperties.getTargetConfig().getLocalAttributes();
            for (ConfigProperties.LocalAttribute attr : attributes) {
                String resultExpression = attr.getResultExpression();
                if (resultExpression != null && !resultExpression.isEmpty()) {
                    String value = parseResultExpression(entry, resultExpression);
                    if (value != null) {
                        updatedAttributes.put(attr.getName(), new Attribute(attr.getName(), value));
                        logger.debug("Set attribute {} to {} for entry DN: {}", attr.getName(), value, entry.getDN());
                    }
                }
            }

            List<Attribute> updatedAttributesList = new ArrayList<>(updatedAttributes.values());
            Entry updatedEntry = new Entry(entry.getDN(), updatedAttributesList);
            SearchResultEntry updatedSearchResultEntry = new SearchResultEntry(updatedEntry);
            SearchResultEntryProtocolOp entryOp = new SearchResultEntryProtocolOp(updatedSearchResultEntry);
            return new LDAPMessage(msgID, entryOp);
        };
    }

    // Парсинг search-expression с учетом атрибута name
    private String parseSearchExpression(SearchResultEntry entry, String expression, String attributeName) {
        if (expression.contains("[[email:username]]")) {
            String email = entry.getAttributeValue(attributeName);
            if (email != null && email.contains("@")) {
                String username = email.split("@")[0];
                String expectedUsername = entry.getAttributeValue(extractAttributeName(expression));
                // Проверяем, что username из email соответствует sAMAccountName
                return username.equals(expectedUsername) ? username : null;
            }
            return null;
        }
        String targetAttribute = extractAttributeName(expression);
        return entry.getAttributeValue(targetAttribute);
    }

    // Парсинг result-expression
    private String parseResultExpression(SearchResultEntry entry, String expression) {
        String attributeName = extractAttributeName(expression);
        String value = entry.getAttributeValue(attributeName);
        if (value != null) {
            return expression.replace("{{" + attributeName + "}}", value);
        }
        return null;
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
