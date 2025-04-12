package edu.uwed.authManager.ldap;

import edu.uwed.authManager.configuration.ConfigProperties;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.ssl.SslContext;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.stereotype.Component;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import java.util.Map;

@Component
public class LdapProxyServer {

    private static final Logger logger = LoggerFactory.getLogger(LdapProxyServer.class);

    private final ConfigProperties configProperties;
    private final SslContext inboundLdapSslContext;
    private final Map<String, LdapTemplate> outboundLdapTemplates;
    private final Map<String, SslContext> outboundLdapSslContexts;
    private final SSLContext inboundLdapTlsContext;
    private final Map<String, SSLContext> outboundLdapTlsContexts;
    private final Map<String, SSLSocketFactory> outboundSslSocketFactories;

    private EventLoopGroup bossGroup;
    private EventLoopGroup workerGroup;
    private Channel ldapChannel;
    private Channel ldapsChannel;

    /*
       public LdapServerInitializer(
            ConfigProperties configProperties,
            SslContext inboundLdapSslContext,
            Map<String, LdapTemplate> outboundLdapTemplates,
            Map<String, SslContext> outboundLdapSslContexts,
            SSLContext inboundLdapTlsContext,
            Map<String, SSLContext> outboundLdapTlsContexts,
            boolean useSsl,
            long maxMessageSize
    ) {
    * */

    @Autowired
    public LdapProxyServer(
            ConfigProperties configProperties,
            @Qualifier("inboundLdapSslContext") SslContext inboundLdapSslContext,
            @Qualifier("inboundLdapTlsContext") SSLContext inboundLdapTlsContext,
            @Qualifier("outboundLdapSslContexts") Map<String, SslContext> outboundLdapSslContexts,
            @Qualifier("outboundLdapTlsContexts") Map<String, SSLContext> outboundLdapTlsContexts,
            @Qualifier("outboundLdapTemplates") Map<String, LdapTemplate> outboundLdapTemplates,
            @Qualifier("outboundSslSocketFactories") Map<String, SSLSocketFactory> outboundSslSocketFactories
    ) {
        this.configProperties = configProperties;
        this.inboundLdapSslContext = inboundLdapSslContext;
        this.inboundLdapTlsContext = inboundLdapTlsContext;
        this.outboundLdapSslContexts = outboundLdapSslContexts;
        this.outboundLdapTlsContexts = outboundLdapTlsContexts;
        this.outboundLdapTemplates = outboundLdapTemplates;
        this.outboundSslSocketFactories = outboundSslSocketFactories;
    }

    @PostConstruct
    public void start() throws Exception {
        bossGroup = new NioEventLoopGroup(1);
        workerGroup = new NioEventLoopGroup();
        ConfigProperties.ProxyConfig proxyConfig = configProperties.getProxyConfig();
        int ldapPort = proxyConfig.getPort().getLdap();
        int ldapsPort = proxyConfig.getPort().getLdaps();
        long maxMessageSize = proxyConfig.getMaxMessageSize();

        // for LDAP[+TLS] connections
        ServerBootstrap ldapBootstrap = new ServerBootstrap();
        ldapBootstrap.group(bossGroup, workerGroup)
                .channel(NioServerSocketChannel.class)
                .childHandler(new LdapServerInitializer(
                    configProperties, inboundLdapSslContext, inboundLdapTlsContext, outboundLdapSslContexts, outboundLdapTlsContexts, outboundLdapTemplates,  outboundSslSocketFactories,false, maxMessageSize
                ))
                .option(ChannelOption.SO_BACKLOG, 128)
                .childOption(ChannelOption.SO_KEEPALIVE, true);

        // for LDAPS connections
        ServerBootstrap ldapsBootstrap = new ServerBootstrap();
        ldapsBootstrap.group(bossGroup, workerGroup)
                .channel(NioServerSocketChannel.class)
                .childHandler(new LdapServerInitializer(
                    configProperties, inboundLdapSslContext, inboundLdapTlsContext, outboundLdapSslContexts, outboundLdapTlsContexts, outboundLdapTemplates, outboundSslSocketFactories, true, maxMessageSize
                ))
                .childHandler(new LdapServerInitializer(
                    configProperties, inboundLdapSslContext, inboundLdapTlsContext, outboundLdapSslContexts, outboundLdapTlsContexts, outboundLdapTemplates, outboundSslSocketFactories,true, maxMessageSize
                ))
                .childHandler(new LdapServerInitializer(
                    configProperties, inboundLdapSslContext, inboundLdapTlsContext, outboundLdapSslContexts, outboundLdapTlsContexts, outboundLdapTemplates, outboundSslSocketFactories, true, maxMessageSize
                ))
                .option(ChannelOption.SO_BACKLOG, 128)
                .childOption(ChannelOption.SO_KEEPALIVE, true);

        ldapChannel = ldapBootstrap.bind(ldapPort).sync().channel();
        ldapsChannel = ldapsBootstrap.bind(ldapsPort).sync().channel();
        logger.info("Started LDAP on port {} and LDAPS on port {}", ldapPort, ldapsPort);
    }

/*          ConfigProperties configProperties,
            SslContext clientSslContext,
            Map<String, LdapTemplate> ldapTemplates,
            Map<String, SslContext> proxySslContexts,
            SSLContext startTlsSslContext,
            Map<String, SSLContext> outgoingSslContexts
            */

    @PreDestroy
    public void stop() {
        if (ldapChannel != null) {
            ldapChannel.close().syncUninterruptibly();
        }
        if (ldapsChannel != null) {
            ldapsChannel.close().syncUninterruptibly();
        }
        if (bossGroup != null) {
            bossGroup.shutdownGracefully();
        }
        if (workerGroup != null) {
            workerGroup.shutdownGracefully();
        }
    }
}
