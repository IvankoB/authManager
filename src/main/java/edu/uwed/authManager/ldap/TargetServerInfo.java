package edu.uwed.authManager.ldap;

import com.unboundid.ldap.protocol.LDAPMessage;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class TargetServerInfo {
    private final String target; // Идентификатор целевого сервера (например, "dc-01")
    private final LDAPMessage ldapMessage; // Парсированное LDAP-сообщение
    private final int messageType; // Тип запроса (BIND_REQUEST, SEARCH_REQUEST и т.д.)
    private final int messageId; // ID сообщения
}
