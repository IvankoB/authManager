package edu.uwed.authManager.ldap;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;
import lombok.*;

import java.util.List;

public class LdapMessageDecoder extends ByteToMessageDecoder {

    private final long maxMessageSize;

    public LdapMessageDecoder(long maxMessageSize) {
        this.maxMessageSize = maxMessageSize;
    }

//    @Override
//    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) {
//        if (in.readableBytes() > maxMessageSize) {
//            throw new IllegalStateException("Message size exceeds maxMessageSize: " + maxMessageSize);
//        }
//        out.add(in.retain());
//    }

    // Внутренний статический класс CustomLDAPMessage
    @Data
    public static class CustomLDAPMessage {
        private int type;
        private ByteBuf content;
        private int resultCode = -1; // Для ExtendedResponse

        @Override
        public String toString() {
            return "CustomLDAPMessage{type=" + type + ", resultCode=" + resultCode + "}";
        }
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) throws Exception {
        if (in.readableBytes() < 2) {
            return;
        }

        in.markReaderIndex();
        byte tag = in.readByte();
        if (tag != 0x30) { // SEQUENCE
            in.resetReaderIndex();
            return;
        }

        int length = readLength(in);
        if (in.readableBytes() < length) {
            in.resetReaderIndex();
            return;
        }

        CustomLDAPMessage message = new CustomLDAPMessage();
        ByteBuf content = in.readBytes(length);
        message.setContent(content);

        content.readerIndex(0);
        if (content.readByte() != 0x02) { // INTEGER (messageID)
            throw new IllegalStateException("Expected INTEGER for messageID");
        }
        int messageIdLength = content.readByte() & 0xFF;
        content.skipBytes(messageIdLength);

        byte typeTag = content.readByte();
        int type = typeTag & 0x1F;
        if (typeTag == 0x60) type = LdapConstants.EXTENDED_REQUEST_TYPE; // ExtendedRequest
        if (typeTag == 0x78) type = LdapConstants.EXTENDED_RESPONSE_TYPE; // ExtendedResponse
        message.setType(type);

        // Если это ExtendedResponse, парсим resultCode
        if (type == LdapConstants.EXTENDED_RESPONSE_TYPE) {
            int responseLength = content.readByte() & 0xFF;
            if (content.readByte() != 0x0A) { // resultCode (ENUMERATED)
                throw new IllegalStateException("Expected ENUMERATED for resultCode");
            }
            int resultCodeLength = content.readByte() & 0xFF;
            if (resultCodeLength != 1) {
                throw new IllegalStateException("Unexpected resultCode length: " + resultCodeLength);
            }
            int resultCode = content.readByte() & 0xFF;
            message.setResultCode(resultCode);
        }

        out.add(message);
    }

    private int readLength(ByteBuf in) {
        int length = in.readByte() & 0xFF;
        if (length > 127) {
            int bytes = length & 0x7F;
            length = 0;
            for (int i = 0; i < bytes; i++) {
                length = (length << 8) | (in.readByte() & 0xFF);
            }
        }
        return length;
    }
}
