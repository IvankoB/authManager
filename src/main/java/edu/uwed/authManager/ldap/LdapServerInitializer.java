package edu.uwed.authManager.ldap;
import edu.uwed.authManager.configuration.ConfigProperties;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.ssl.SslContext;
import org.springframework.ldap.core.LdapTemplate;

import javax.net.ssl.SSLContext;
import java.util.Map;

public class LdapServerInitializer extends ChannelInitializer<SocketChannel> {

    private final ConfigProperties configProperties;
    private final SslContext sslContext;
    private final Map<String, LdapTemplate> ldapTemplates;
    private final Map<String, SslContext> proxySslContexts;
    private final SSLContext startTlsSslContext;
    private final Map<String, SSLContext> outgoingSslContexts;
    private final boolean useSsl;
    private final long maxMessageSize;

    public LdapServerInitializer(
            ConfigProperties configProperties,
            SslContext sslContext,
            Map<String, LdapTemplate> ldapTemplates,
            Map<String, SslContext> proxySslContexts,
            SSLContext startTlsSslContext,
            Map<String, SSLContext> outgoingSslContexts,
            boolean useSsl,
            long maxMessageSize
    ) {
        this.configProperties = configProperties;
        this.sslContext = sslContext;
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
            pipeline.addLast(sslContext.newHandler(ch.alloc()));
        }
        pipeline.addLast(new LdapRequestHandler(configProperties, sslContext, ldapTemplates, proxySslContexts, startTlsSslContext, outgoingSslContexts));
    }


}
