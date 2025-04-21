package edu.uwed.authManager.ldap;

import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.SearchResultEntryProtocolOp;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.SearchResultEntry;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Predicate;
import java.util.stream.Collectors;

public class LdapSearchMITM {

    //////////// Создаем предикат для фильтрации
    public static Predicate<SearchResultEntry> filter = entry -> {
        String mail = entry.getAttributeValue("mail");
        String cn = entry.getAttributeValue("cn");
        return true;
        //return (mail != null && mail.contains("@example.com")) &&
    };

    //////////// Создаем функцию-обработчик для модификации записи
    public static BiFunction<SearchResultEntry, Integer, LDAPMessage> entryProcessor = (entry, msgID) -> {
        // Извлекаем текущие атрибуты записи в Map
        Map<String, Attribute> updatedAttributes = entry.getAttributes().stream()
                .collect(Collectors.toMap(
                        Attribute::getName,
                        attr -> attr,
                        (attr1, attr2) -> attr1, // В случае дубликатов берем первый атрибут
                        HashMap::new
                ));

        //// Пример модификации атрибутов:
        //// 1. Удаляем атрибут cn
        //updatedAttributes.removeIf(attr -> attr.getName().equals("cn"));

        //// 2. Изменяем атрибут mail
        //updatedAttributes.removeIf(attr -> attr.getName().equals("mail"));
        //updatedAttributes.add(new Attribute("mail", "newemail@example.com"));

        //// 3. Добавляем новый атрибут telephoneNumber
        //updatedAttributes.add(new Attribute("telephoneNumber", "+1234567890"));

        updatedAttributes.put(
                "registeredAddress",
                new Attribute("registeredAddress", updatedAttributes.get("sAMAccountName").getValue() + "@uwed.uz")
        );
        updatedAttributes.put(
                "postalAddress",
                new Attribute("postalAddress", updatedAttributes.get("sAMAccountName").getValue() + "@uwed.ac.uz")
        );

        // Преобразуем Map обратно в List для создания Entry
        List<Attribute> updatedAttributesList = new ArrayList<>(updatedAttributes.values());
        // Создаем новый Entry с обновленными атрибутами
        Entry updatedEntry = new Entry(entry.getDN(), updatedAttributesList);
        // Преобразуем обновленный Entry в SearchResultEntry
        SearchResultEntry updatedSearchResultEntry = new SearchResultEntry(updatedEntry);
        // Преобразуем SearchResultEntry в SearchResultEntryProtocolOp
        SearchResultEntryProtocolOp entryOp = new SearchResultEntryProtocolOp(updatedSearchResultEntry);
        // Создаем LDAPMessage с переданным messageID
        return new LDAPMessage(msgID, entryOp);
    };

}
