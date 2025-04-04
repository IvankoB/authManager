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
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.annotation.Bean;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
public class LdapProxyServer {

    private static final Logger logger = LoggerFactory.getLogger(LdapProxyServer.class);

    private final ConfigProperties configProperties;
    private final SslContext sslContext;
    private final Map<String, LdapTemplate> ldapTemplates;
    private final Map<String, SslContext> proxySslContexts;

    private EventLoopGroup bossGroup;
    private EventLoopGroup workerGroup;
    private Channel ldapChannel;
    private Channel ldapsChannel;

    @Autowired
    public LdapProxyServer(
            ConfigProperties configProperties,
            @Qualifier("ldaps") SslContext sslContext,
            Map<String, LdapTemplate> ldapTemplates,
            Map<String, SslContext> proxySslContexts
    ) {
        this.configProperties = configProperties;
        this.sslContext = sslContext;
        this.ldapTemplates = ldapTemplates;
        this.proxySslContexts = proxySslContexts;
    }

    @PostConstruct
    public void start() throws Exception {
        bossGroup = new NioEventLoopGroup(1);
        workerGroup = new NioEventLoopGroup();
        ConfigProperties.ProxyConfig proxyConfig = configProperties.getProxyConfig();
        int ldapPort = proxyConfig.getPort().getLdap();
        int ldapsPort = proxyConfig.getPort().getLdaps();
        long maxMessageSize = proxyConfig.getMaxMessageSize();

        ServerBootstrap ldapBootstrap = new ServerBootstrap();
        ldapBootstrap.group(bossGroup, workerGroup)
                .channel(NioServerSocketChannel.class)
                .childHandler(new LdapServerInitializer(configProperties, sslContext, ldapTemplates, proxySslContexts, false, maxMessageSize))
                .option(ChannelOption.SO_BACKLOG, 128)
                .childOption(ChannelOption.SO_KEEPALIVE, true);

        ServerBootstrap ldapsBootstrap = new ServerBootstrap();
        ldapsBootstrap.group(bossGroup, workerGroup)
                .channel(NioServerSocketChannel.class)
                .childHandler(new LdapServerInitializer(configProperties, sslContext, ldapTemplates, proxySslContexts, true, maxMessageSize))
                .option(ChannelOption.SO_BACKLOG, 128)
                .childOption(ChannelOption.SO_KEEPALIVE, true);

        ldapChannel = ldapBootstrap.bind(ldapPort).sync().channel();
        ldapsChannel = ldapsBootstrap.bind(ldapsPort).sync().channel();
        logger.info("Started LDAP on port {} and LDAPS on port {}", ldapPort, ldapsPort);
    }

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
