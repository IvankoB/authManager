package edu.uwed.authManager.ldap;
import edu.uwed.authManager.configuration.ConfigProperties;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import io.netty.handler.ssl.SslContext;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

public class LdapServerInitializer extends ChannelInitializer<SocketChannel> {

    private final ConfigProperties configProperties;
    private final SslContext proxySslContext;
    private final SSLContext proxyTlsContext;
    private final SSLSocketFactory targetSecureSocketFactory;
    private final LDAPConnectionPoolFactory targetConnectionPoolFactory;
    private final LdapMITM ldapMITM;
    private final boolean useSsl;

    public LdapServerInitializer(
            ConfigProperties configProperties,
            SslContext proxySslContext,
            SSLContext proxyTlsContext,
            SSLSocketFactory targetSecureSocketFactory,
            LDAPConnectionPoolFactory targetConnectionPoolFactory,
            LdapMITM ldapMITM,
            boolean useSsl
    ) {
        this.configProperties = configProperties;
        this.proxySslContext = proxySslContext;
        this.proxyTlsContext = proxyTlsContext;
        this.targetSecureSocketFactory = targetSecureSocketFactory;
        this.targetConnectionPoolFactory = targetConnectionPoolFactory;
        this.ldapMITM = ldapMITM;
        this.useSsl = useSsl;
    }

    @Override
    protected void initChannel(SocketChannel ch) {
        ChannelPipeline pipeline = ch.pipeline();
        if (useSsl) { // если канал настроен на LDAPS-коеннекты, то начинать соединения с утряски SSL
            pipeline.addLast(proxySslContext.newHandler(ch.alloc()));
        }
        int timeout = configProperties.getTargetConfig().getClientTimeoutSec();
        // Добавляем логирование сырых данных
        pipeline.addFirst("rawLogger", new LoggingHandler(LogLevel.DEBUG));
        // Добавляем тайм-аут на завершения чтения от клиента (5 секунд)
//////////        pipeline.addLast(new ReadTimeoutHandler(timeout));
        // Добавляем тайм-аут на запись к клиенту (5 секунд)
/////////        pipeline.addLast(new WriteTimeoutHandler(timeout));
                // Добавляем обработчик запросов
        pipeline.addLast(new LdapRequestHandler(
            configProperties, proxySslContext, proxyTlsContext, targetSecureSocketFactory, targetConnectionPoolFactory, ldapMITM
        ));
    }


}
