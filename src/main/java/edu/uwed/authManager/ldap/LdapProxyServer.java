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
import org.springframework.stereotype.Component;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

@Component
public class LdapProxyServer {

    private static final Logger logger = LoggerFactory.getLogger(LdapProxyServer.class);

    private final ConfigProperties configProperties;
    private final SslContext proxySslContext;
    private final SSLContext proxyTlsContext;
    private final SSLSocketFactory targetSecureSocketFactory;
    private final LDAPConnectionPoolFactory targetConnectionPoolFactory;

    private EventLoopGroup bossGroup;
    private EventLoopGroup workerGroup;
    private Channel ldapChannel;
    private Channel ldapsChannel;

    @Autowired
    public LdapProxyServer(
            ConfigProperties configProperties,
            @Qualifier("proxyLdapSslContext") SslContext proxySslContext,
            @Qualifier("proxyLdapTlsContext") SSLContext proxyTlsContext,
            @Qualifier("targetLdapSecureSocketFactory") SSLSocketFactory targetSecureSocketFactory,
            @Qualifier("targetLdapConnectionPoolFactory") LDAPConnectionPoolFactory targetConnectionPoolFactory
    ) {
        this.configProperties = configProperties;
        this.proxySslContext = proxySslContext;
        this.proxyTlsContext = proxyTlsContext;
        this.targetSecureSocketFactory = targetSecureSocketFactory;
        this.targetConnectionPoolFactory = targetConnectionPoolFactory;
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
                    configProperties, proxySslContext, proxyTlsContext, targetSecureSocketFactory,targetConnectionPoolFactory,false, maxMessageSize
                ))
                .option(ChannelOption.SO_BACKLOG, 128)
                .childOption(ChannelOption.SO_KEEPALIVE, true);

        // for LDAPS connections
        ServerBootstrap ldapsBootstrap = new ServerBootstrap();
        ldapsBootstrap.group(bossGroup, workerGroup)
                .channel(NioServerSocketChannel.class)
                .childHandler(new LdapServerInitializer(
                    configProperties, proxySslContext, proxyTlsContext, targetSecureSocketFactory,targetConnectionPoolFactory,true, maxMessageSize
                ))
                .childHandler(new LdapServerInitializer(
                    configProperties, proxySslContext, proxyTlsContext, targetSecureSocketFactory,targetConnectionPoolFactory,true, maxMessageSize
                ))
                .childHandler(new LdapServerInitializer(
                    configProperties, proxySslContext, proxyTlsContext, targetSecureSocketFactory,targetConnectionPoolFactory,true, maxMessageSize
                ))
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
