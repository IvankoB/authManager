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
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.stereotype.Component;

import javax.net.ssl.SSLException;
import java.security.cert.CertificateException;

@Component
@RequiredArgsConstructor
public class LdapProxyServer {

    private static final Logger logger = LoggerFactory.getLogger(LdapProxyServer.class);

    private final ConfigProperties configProperties;
    private final LdapRequestHandler ldapRequestHandler;

//    private final SslBundles sslBundles;
    private final SslContext sslContext;

    private EventLoopGroup bossGroup;
    private EventLoopGroup workerGroup;
    private Channel ldapChannel;
    private Channel ldapsChannel;

    @PostConstruct
    public void start() throws InterruptedException {
        try {
            SslBundle sslBundle = sslBundles.getBundle("dc01LdapProxy"); // строка 36
            SslContext sslContext = sslBundle.createSslContext();        // строка 37

            bossGroup = new NioEventLoopGroup(1);                        // строка 38
            workerGroup = new NioEventLoopGroup();                       // строка 39
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
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize LDAPS server", e);
        }
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
