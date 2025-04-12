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
    private final SslContext inboundLdapSslContext;
    private final Map<String, LdapTemplate> outboundLdapTemplates;
    private final Map<String, SslContext> outboundLdapSslContexts;
    private final SSLContext inboundLdapTlsContext;
    private final Map<String, SSLContext> outboundLdapTlsContexts;
    private final Map<String, SSLSocketFactory> outboundSslSocketFactories;
    private final boolean useSsl;
    private final long maxMessageSize;

    public LdapServerInitializer(
            ConfigProperties configProperties,
            SslContext inboundLdapSslContext,
            SSLContext inboundLdapTlsContext,
            Map<String, SslContext> outboundLdapSslContexts,
            Map<String, SSLContext> outboundLdapTlsContexts,
            Map<String, LdapTemplate> outboundLdapTemplates,
            Map<String, SSLSocketFactory> outboundSslSocketFactories,
            boolean useSsl,
            long maxMessageSize
    ) {
        this.configProperties = configProperties;
        this.inboundLdapSslContext = inboundLdapSslContext;
        this.outboundLdapTemplates = outboundLdapTemplates;
        this.outboundLdapSslContexts = outboundLdapSslContexts;
        this.inboundLdapTlsContext = inboundLdapTlsContext;
        this.outboundLdapTlsContexts = outboundLdapTlsContexts;
        this.outboundSslSocketFactories = outboundSslSocketFactories;
        this.useSsl = useSsl;
        this.maxMessageSize = maxMessageSize;
    }

    @Override
    protected void initChannel(SocketChannel ch) {
        ChannelPipeline pipeline = ch.pipeline();
        if (useSsl) {
            pipeline.addLast(inboundLdapSslContext.newHandler(ch.alloc()));
        }
        pipeline.addLast(new LdapRequestHandler(
            configProperties, inboundLdapSslContext, inboundLdapTlsContext, outboundLdapSslContexts, outboundLdapTlsContexts, outboundLdapTemplates,outboundSslSocketFactories
        ));
    }

/*    ConfigProperties configProperties,
    SslContext inboundLdapSslContext,
    SSLContext inboundLdapTlsContext,
    Map<String, SslContext> outboundLdapSslContexts,
    Map<String, SSLContext> outboundLdapTlsContexts,
    Map<String, LdapTemplate> outboundLdapTemplates
 */

}
