package edu.uwed.authManager.ldap;

import io.netty.channel.ChannelInitializer;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslHandler;

public class LdapServerInitializer extends ChannelInitializer<SocketChannel> {

    private final LdapRequestHandler ldapRequestHandler;
    private final SslContext sslContext;
    private final boolean isLdaps;
    private final long maxMessageSize;

    public LdapServerInitializer(LdapRequestHandler ldapRequestHandler, SslContext sslContext, boolean isLdaps, long maxMessageSize) {
        this.ldapRequestHandler = ldapRequestHandler;
        this.sslContext = sslContext;
        this.isLdaps = isLdaps;
        this.maxMessageSize = maxMessageSize;
    }

    @Override
    protected void initChannel(SocketChannel ch) {
        if (isLdaps) {
            SslHandler sslHandler = sslContext.newHandler(ch.alloc());
            ch.pipeline().addLast(sslHandler);
        }
        ch.pipeline().addLast(new LdapMessageDecoder(maxMessageSize));
        ch.pipeline().addLast(ldapRequestHandler);
    }
}
