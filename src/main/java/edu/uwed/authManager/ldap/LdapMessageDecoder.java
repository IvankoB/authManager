package edu.uwed.authManager.ldap;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;

import java.util.List;

public class LdapMessageDecoder extends ByteToMessageDecoder {

    private final long maxMessageSize;

    public LdapMessageDecoder(long maxMessageSize) {
        this.maxMessageSize = maxMessageSize;
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) {
        if (in.readableBytes() > maxMessageSize) {
            throw new IllegalStateException("Message size exceeds maxMessageSize: " + maxMessageSize);
        }
        out.add(in.retain());
    }
}
