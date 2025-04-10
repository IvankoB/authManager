package edu.uwed.authManager.ldap;
import edu.uwed.authManager.configuration.ConfigProperties;
import edu.uwed.authManager.services.LdapService;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslHandler;
import org.springframework.ldap.core.LdapTemplate;

import javax.net.ssl.SSLContext;
import java.util.Map;
import java.util.Objects;

public class LdapServerInitializer extends ChannelInitializer<SocketChannel> {

    private final ConfigProperties configProperties;
    private final SslContext ldapsSslContext;
    private final LdapService ldapService;
    private final Map<String, LdapTemplate> ldapTemplates;
    private final Map<String, SslContext> proxySslContexts;
    private final SSLContext startTlsSslContext;
    private final Map<String, SSLContext> outgoingSslContexts;
    private final boolean useSsl;
    private final long maxMessageSize;

    public LdapServerInitializer(
            ConfigProperties configProperties,
            SslContext ldapsSslContext,
            LdapService ldapService,
            Map<String, LdapTemplate> ldapTemplates,
            Map<String, SslContext> proxySslContexts,
            SSLContext startTlsSslContext,
            Map<String, SSLContext> outgoingSslContexts,
            boolean useSsl,
            long maxMessageSize
    ) {
        this.configProperties = configProperties;
        this.ldapsSslContext = ldapsSslContext;
        this.ldapService = ldapService;
        this.ldapTemplates = ldapTemplates;
        this.proxySslContexts = proxySslContexts;
        this.startTlsSslContext = startTlsSslContext;
        this.outgoingSslContexts = outgoingSslContexts;
        this.useSsl = useSsl;
        this.maxMessageSize = maxMessageSize;
    }

    @Override
    protected void initChannel(SocketChannel ch) {
        ChannelPipeline pipeline = ch.pipeline();
        if (useSsl) {
            SslHandler sslHandler = ldapsSslContext.newHandler(ch.alloc());
            pipeline.addLast("ssl", sslHandler);
            sslHandler.handshakeFuture().addListener(future -> {
                if (future.isSuccess()) {
                    // Точка останова здесь
                    ch.read();
                } else {
                    // Логирование ошибки
                }
            });
        }
        pipeline.addLast(new LdapMessageDecoder(maxMessageSize));
        pipeline.addLast(new LdapRequestHandler(
                configProperties,
                ldapService,
                ldapsSslContext,
                startTlsSslContext,
                ldapTemplates,
                proxySslContexts,
                outgoingSslContexts
        ));
    }

}
