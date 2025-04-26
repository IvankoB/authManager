package edu.uwed.authManager.ldap;


import com.unboundid.ldap.protocol.BindResponseProtocolOp;
import com.unboundid.ldap.protocol.ExtendedResponseProtocolOp;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.SearchResultDoneProtocolOp;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LdapUtils {
    private static final Logger logger = LoggerFactory.getLogger(LdapUtils.class);
    private LdapUtils() {} // Запрещаем создание экземпляров

    public static void sendSearchDoneResponse(ChannelHandlerContext ctx, int messageId, ResultCode resultCode) {
        ResultCode code = resultCode != null ? resultCode : ResultCode.OPERATIONS_ERROR;
        logger.debug("Sending SearchDone response for messageId: {}, resultCode: {}", messageId, code);
        try {
            SearchResultDoneProtocolOp doneOp = new SearchResultDoneProtocolOp(new LDAPResult(messageId, code));
            LDAPMessage doneMessage = new LDAPMessage(messageId, doneOp);
            byte[] doneBytes = doneMessage.encode().encode();
            ByteBuf doneBuf = ctx.alloc().buffer(doneBytes.length);
            doneBuf.writeBytes(doneBytes);
            ctx.writeAndFlush(doneBuf).addListener(future -> {
                if (!future.isSuccess()) {
                    logger.error("Failed to send search done response for messageId: {}", messageId, future.cause());
                    ctx.close();
                }
            });
        } catch (Exception e) {
            logger.error("Failed to encode search done response for messageId: {}", messageId, e);
            ctx.close();
        }
    }

    public static void sendBindResponse(ChannelHandlerContext ctx, int messageId, ResultCode resultCode) {
        ResultCode code = resultCode != null ? resultCode : ResultCode.OPERATIONS_ERROR;
        logger.debug("Sending Bind response for messageId: {}, resultCode: {}", messageId, code);
        try {
            BindResponseProtocolOp bindOp = new BindResponseProtocolOp(new LDAPResult(messageId, code));
            LDAPMessage bindMessage = new LDAPMessage(messageId, bindOp);
            byte[] doneBytes = bindMessage.encode().encode();
            ByteBuf doneBuf = ctx.alloc().buffer(doneBytes.length);
            doneBuf.writeBytes(doneBytes);
            ctx.writeAndFlush(doneBuf).addListener(future -> {
                if (!future.isSuccess()) {
                    logger.error("Failed to send bind response for messageId: {}", messageId, future.cause());
                    ctx.close();
                }
            });
        } catch (Exception e) {
            logger.error("Failed to encode bind response for messageId: {}", messageId, e);
            ctx.close();
        }
    }

    // защищенный канал с клиентом : наш ответ "TLS ОК" клиенту и ожидание подтверждения от него
    public static void sendStartTlsResponse(ChannelHandlerContext ctx, int messageId) {
        logger.debug("Sending StartTLS response for messageId: {}", messageId);
        try {
            ExtendedResponseProtocolOp responseOp = new ExtendedResponseProtocolOp(new LDAPResult(messageId, ResultCode.SUCCESS));
            LDAPMessage responseMessage = new LDAPMessage(messageId, responseOp);
            byte[] responseBytes = responseMessage.encode().encode();
            ByteBuf responseBuf = ctx.alloc().buffer(responseBytes.length);
            responseBuf.writeBytes(responseBytes);
            ctx.writeAndFlush(responseBuf).addListener(future -> {
                if (!future.isSuccess()) {
                    logger.error("Failed to send StartTLS response for messageId: {}", messageId, future.cause());
                    ctx.close();
                }
            });
        } catch (Exception e) {
            logger.error("Failed to encode StartTLS response for messageId: {}", messageId, e);
            ctx.close();
        }
    }

}
