package edu.uwed.authManager.ldap;
import edu.uwed.authManager.configuration.ConfigProperties;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.timeout.ReadTimeoutHandler;
import io.netty.handler.timeout.WriteTimeoutHandler;
import org.springframework.ldap.core.LdapTemplate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import java.util.Map;

public class LdapServerInitializer extends ChannelInitializer<SocketChannel> {

    private final ConfigProperties configProperties;
    private final SslContext proxySslContext;
    private final SSLContext proxyTlsContext;
    private final SSLSocketFactory targetSecureSocketFactory;
    private final LDAPConnectionPoolFactory targetConnectionPoolFactory;
    private final LdapSearchMITM ldapSearchMITM;
    private final boolean useSsl;

    public LdapServerInitializer(
            ConfigProperties configProperties,
            SslContext proxySslContext,
            SSLContext proxyTlsContext,
            SSLSocketFactory targetSecureSocketFactory,
            LDAPConnectionPoolFactory targetConnectionPoolFactory,
            LdapSearchMITM ldapSearchMITM,
            boolean useSsl
    ) {
        this.configProperties = configProperties;
        this.proxySslContext = proxySslContext;
        this.proxyTlsContext = proxyTlsContext;
        this.targetSecureSocketFactory = targetSecureSocketFactory;
        this.targetConnectionPoolFactory = targetConnectionPoolFactory;
        this.ldapSearchMITM = ldapSearchMITM;
        this.useSsl = useSsl;
    }

    @Override
    protected void initChannel(SocketChannel ch) {
        ChannelPipeline pipeline = ch.pipeline();
        if (useSsl) { // если канал настроен на LDAPS-коеннекты, то начинать соединения с утряски SSL
            pipeline.addLast(proxySslContext.newHandler(ch.alloc()));
        }
        // Добавляем логирование сырых данных
        pipeline.addFirst("rawLogger", new LoggingHandler(LogLevel.DEBUG));
        // Добавляем тайм-аут на завершения чтения от клиента (5 секунд)
////////        pipeline.addLast(new ReadTimeoutHandler(5));
        // Добавляем тайм-аут на запись к клиенту (5 секунд)
///////        pipeline.addLast(new WriteTimeoutHandler(5));
        // Добавляем декодер для сборки полных LDAP-сообщений
        //pipeline.addLast(new LdapFrameDecoder());
        // Добавляем обработчик запросов
        pipeline.addLast(new LdapRequestHandler(
            configProperties, proxySslContext, proxyTlsContext, targetSecureSocketFactory, targetConnectionPoolFactory,ldapSearchMITM
        ));
    }


}
