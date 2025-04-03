package edu.uwed.authManager.components;

import edu.uwed.authManager.configuration.ConfigProperties;
import edu.uwed.authManager.services.LdapRequestHandler;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.springframework.stereotype.Component;

@Component
public class LdapProxyServer {

    private final LdapRequestHandler requestHandler;
    private final ConfigProperties configProperties;

    private EventLoopGroup bossGroup;
    private EventLoopGroup workerGroup;
    private Channel ldapChannel;
    private Channel ldapsChannel;

    public LdapProxyServer(
            LdapRequestHandler requestHandler,
            ConfigProperties configProperties
    ) {
        this.requestHandler = requestHandler;
        this.configProperties = configProperties;
    }

    @PostConstruct
    public void startLdapProxy() throws InterruptedException {
        ConfigProperties.ProxyConfig proxyConfig = configProperties.getProxyConfig();

        bossGroup = new NioEventLoopGroup(1);
        workerGroup = new NioEventLoopGroup();

        try {
            ServerBootstrap ldapBootstrap = new ServerBootstrap();
            ldapBootstrap.group(bossGroup, workerGroup)
                    .channel(NioServerSocketChannel.class)
                    .childHandler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel ch) {
                            ch.pipeline().addLast(new LdapMessageHandler(false));
                        }
                    })
                    .option(ChannelOption.SO_BACKLOG, 128)
                    .childOption(ChannelOption.SO_KEEPALIVE, true);

            ServerBootstrap ldapsBootstrap = new ServerBootstrap();
            ldapsBootstrap.group(bossGroup, workerGroup)
                    .channel(NioServerSocketChannel.class)
                    .childHandler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel ch) {
                            ch.pipeline().addFirst(requestHandler.getSslContext().newHandler(ch.alloc()));
                            ch.pipeline().addLast(new LdapMessageHandler(true));
                        }
                    })
                    .option(ChannelOption.SO_BACKLOG, 128)
                    .childOption(ChannelOption.SO_KEEPALIVE, true);

            ChannelFuture ldapFuture = ldapBootstrap.bind(proxyConfig.getPort().getLdap()).sync();
            ChannelFuture ldapsFuture = ldapsBootstrap.bind(proxyConfig.getPort().getLdaps()).sync();

            ldapChannel = ldapFuture.channel();
            ldapsChannel = ldapsFuture.channel();

            System.out.println("LdapProxyServer: Started LDAP on port " + proxyConfig.getPort().getLdap() + " and LDAPS on port " + proxyConfig.getPort().getLdaps());
        } catch (Exception e) {
            System.err.println("LdapProxyServer: Failed to start: " + e.getMessage());
            bossGroup.shutdownGracefully();
            workerGroup.shutdownGracefully();
            throw new RuntimeException("Failed to start LDAP proxy", e);
        }
    }

    @PreDestroy
    public void stopLdapProxy() {
        if (ldapChannel != null) ldapChannel.close();
        if (ldapsChannel != null) ldapsChannel.close();
        if (bossGroup != null) bossGroup.shutdownGracefully();
        if (workerGroup != null) workerGroup.shutdownGracefully();
        System.out.println("LdapProxyServer: Stopped");
    }

    private class LdapMessageHandler extends SimpleChannelInboundHandler<ByteBuf> {
        private final boolean isLdaps;

        public LdapMessageHandler(boolean isLdaps) {
            this.isLdaps = isLdaps;
        }

        @Override
        protected void channelRead0(ChannelHandlerContext ctx, ByteBuf msg) throws Exception {
            requestHandler.handleRequest(ctx, msg, isLdaps);
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            System.err.println("LdapProxyServer (" + (isLdaps ? "LDAPS" : "LDAP") + "): Error: " + cause.getMessage());
            ctx.close();
        }
    }
}