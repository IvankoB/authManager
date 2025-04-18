package edu.uwed.authManager.ldap;
import edu.uwed.authManager.configuration.ConfigProperties;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.ssl.SslContext;
import org.springframework.ldap.core.LdapTemplate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import java.util.Map;

public class LdapServerInitializer extends ChannelInitializer<SocketChannel> {

    private final ConfigProperties configProperties;
    private final SslContext proxySslContext;
    private final SSLContext proxyTlsContext;
    private final SSLSocketFactory targetSecureSocketFactory;
    private final boolean useSsl;
    private final long maxMessageSize;

    public LdapServerInitializer(
            ConfigProperties configProperties,
            SslContext proxySslContext,
            SSLContext proxyTlsContext,
            SSLSocketFactory targetSecureSocketFactory,
            boolean useSsl,
            long maxMessageSize
    ) {
        this.configProperties = configProperties;
        this.proxySslContext = proxySslContext;
        this.proxyTlsContext = proxyTlsContext;
        this.targetSecureSocketFactory = targetSecureSocketFactory;
        this.useSsl = useSsl;
        this.maxMessageSize = maxMessageSize;
    }

    @Override
    protected void initChannel(SocketChannel ch) {
        ChannelPipeline pipeline = ch.pipeline();
        if (useSsl) { // если канал настроен на LDAPS-коеннекты, то начинать соединения с утряски SSL
            pipeline.addLast(proxySslContext.newHandler(ch.alloc()));
        }
        pipeline.addLast(new LdapRequestHandler(
            configProperties, proxySslContext, proxyTlsContext, targetSecureSocketFactory, maxMessageSize
        ));
    }


}
