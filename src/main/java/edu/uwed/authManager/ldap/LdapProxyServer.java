package edu.uwed.authManager.ldap;

import edu.uwed.authManager.configuration.ConfigProperties;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.SelfSignedCertificate;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.net.ssl.SSLException;
import java.security.cert.CertificateException;

@Component
@RequiredArgsConstructor
public class LdapProxyServer {

    private static final Logger logger = LoggerFactory.getLogger(LdapProxyServer.class);

    private final ConfigProperties configProperties;
    private final LdapRequestHandler ldapRequestHandler;

    private EventLoopGroup bossGroup;
    private EventLoopGroup workerGroup;
    private Channel ldapChannel;
    private Channel ldapsChannel;

    @PostConstruct
    public void start() throws CertificateException, InterruptedException {
        SelfSignedCertificate ssc = new SelfSignedCertificate();
        SslContext sslContext;
        try {
            sslContext = SslContextBuilder.forServer(ssc.certificate(), ssc.privateKey()).build();
        } catch (SSLException e) {
            throw new RuntimeException(e);
        }

        bossGroup = new NioEventLoopGroup(1);
        workerGroup = new NioEventLoopGroup();
        int ldapPort = configProperties.getLdapProxy().getPortLdap();
        int ldapsPort = configProperties.getLdapProxy().getPortLdaps();
        long maxMessageSize = configProperties.getLdapProxy().getMaxMessageSize();

        ServerBootstrap ldapBootstrap = new ServerBootstrap();
        ldapBootstrap.group(bossGroup, workerGroup)
                .channel(NioServerSocketChannel.class)
                .childHandler(new LdapServerInitializer(ldapRequestHandler, sslContext, false, maxMessageSize))
                .option(ChannelOption.SO_BACKLOG, 128)
                .childOption(ChannelOption.SO_KEEPALIVE, true);

        ServerBootstrap ldapsBootstrap = new ServerBootstrap();
        ldapsBootstrap.group(bossGroup, workerGroup)
                .channel(NioServerSocketChannel.class)
                .childHandler(new LdapServerInitializer(ldapRequestHandler, sslContext, true, maxMessageSize))
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
