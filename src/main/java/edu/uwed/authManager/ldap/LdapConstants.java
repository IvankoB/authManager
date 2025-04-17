package edu.uwed.authManager.ldap;

public class LdapConstants {
    // Типы сообщений
    public static final int EXTENDED_REQUEST_TYPE = 96;  // ExtendedRequest
    public static final int EXTENDED_RESPONSE_TYPE = 97; // ExtendedResponse

    // Константы для StartTLS
    public static final int START_TLS_MESSAGE_ID = 1;   // messageId для StartTLS

    public static final String START_TLS_OID = "1.3.6.1.4.1.1466.20037";

    private LdapConstants() {
        // Приватный конструктор, чтобы предотвратить создание экземпляров
    }

    public enum LDAP_PROTOCOL {
        LDAP, LDAPS, LDAP_TLS
    }

    public enum BIND_STATUS {
        NONE, SUCCESS, UPLINK, FAILURE
    }
}

