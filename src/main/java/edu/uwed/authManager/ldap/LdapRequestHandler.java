package edu.uwed.authManager.ldap;

import edu.uwed.authManager.configuration.ConfigProperties;
import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.ssl.SslContext;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class LdapRequestHandler extends SimpleChannelInboundHandler<ByteBuf> {

    // Beans to autowire by the constructor
    private final ConfigProperties configProperties;
    private final SslContext clientSslContext;
    private final Map<String, SslContext> proxySslContexts;
    private final Map<String, LdapTemplate> ldapTemplates;

    private Channel outboundChannel;
    private static final Logger logger = LoggerFactory.getLogger(LdapRequestHandler.class);

    @Autowired
    public LdapRequestHandler(
            ConfigProperties configProperties,
            SslContext clientSslContext,
            Map<String, LdapTemplate> ldapTemplates,
            Map<String, SslContext> proxySslContexts
    ) {
        this.clientSslContext = clientSslContext;
        this.proxySslContexts = proxySslContexts;
        this.configProperties = configProperties;
        this.ldapTemplates = ldapTemplates;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, ByteBuf msg) {
        logger.info("Received LDAP message: {}", msg);
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) {
        logger.info("Client connected: {}", ctx.channel().remoteAddress());
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        logger.info("Client disconnected: {}", ctx.channel().remoteAddress());
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        logger.error("Error in LDAP request handling", cause);
        ctx.close();
    }
}
