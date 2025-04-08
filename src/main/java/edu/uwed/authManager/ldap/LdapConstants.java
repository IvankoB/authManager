package edu.uwed.authManager.ldap;

public class LdapConstants {
    // Типы сообщений
    public static final int EXTENDED_REQUEST_TYPE = 96;  // ExtendedRequest
    public static final int EXTENDED_RESPONSE_TYPE = 97; // ExtendedResponse

    // Константы для StartTLS
    public static final int START_TLS_MESSAGE_ID = 1;   // messageId для StartTLS

    private LdapConstants() {
        // Приватный конструктор, чтобы предотвратить создание экземпляров
    }
}
