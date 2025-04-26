package edu.uwed.authManager.ldap;

import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.SearchResultDoneProtocolOp;
import com.unboundid.ldap.protocol.SearchResultEntryProtocolOp;
import com.unboundid.ldap.sdk.*;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Predicate;

public class LdapProxyStreamingSearchResultListener implements AsyncSearchResultListener {

    private static final Logger logger = LoggerFactory.getLogger(LdapProxyStreamingSearchResultListener.class);

    private final ChannelHandlerContext ctx;
    private final Predicate<SearchResultEntry> filter;
    private final BiFunction<SearchResultEntry, Integer, LDAPMessage> entryProcessor;
    //private final int serverMessageId;
    private final int clientMessageId;
    private final LDAPConnectionPool pool;
    private final LDAPConnection conn;


    public LdapProxyStreamingSearchResultListener(
            ChannelHandlerContext ctx,
            Predicate<SearchResultEntry> filter,
            BiFunction<SearchResultEntry, Integer, LDAPMessage> entryProcessor,
            //int serverMessageId
            int clientMessageId,
            LDAPConnectionPool pool, LDAPConnection conn
    ) {
        this.ctx = ctx;
        this.filter = filter;
        this.entryProcessor = entryProcessor;
        //this.serverMessageId = serverMessageId;
        this.clientMessageId = clientMessageId;
        this.pool = pool;
        this.conn = conn;
    }

    @Override
    public void searchEntryReturned(SearchResultEntry searchEntry) {
        logger.debug("Entry attributes for clientMessageId: {}, DN: {}, attributes: {}",
                clientMessageId, searchEntry.getDN(), searchEntry.getAttributes());
    if (filter.test(searchEntry)) {
            logger.debug("Sending search entry for messageId: {}, DN: {}", clientMessageId, searchEntry.getDN());
            LDAPMessage message = entryProcessor.apply(searchEntry, clientMessageId);
            ByteBuf buf = ctx.alloc().buffer();
            buf.writeBytes(message.encode().encode());
            ctx.writeAndFlush(buf).addListener(future -> {
                if (!future.isSuccess()) {
                    logger.error("Failed to send search entry for messageId: {}", clientMessageId, future.cause());
                }
            });
        }
    }

    // Реализация других методов SearchResultListener (если нужно)
    @Override
    public void searchReferenceReturned(SearchResultReference reference) {
        logger.debug("Search reference received for messageId: {}, URLs: {}", clientMessageId, reference.getReferralURLs());
        // Отправить ссылки клиенту, если требуется
    }

    @Override
    public void searchResultReceived(AsyncRequestID requestID, SearchResult searchResult) {
        logger.debug("Search result for clientMessageId: {}, resultCode: {}, entries: {}, connection: {}",
                clientMessageId, searchResult.getResultCode(), searchResult.getEntryCount(), conn.hashCode());
        if (searchResult.getResultCode().equals(ResultCode.SUCCESS)) {
            logger.info("Search completed for messageId: {}", clientMessageId);
            LdapUtils.sendSearchDoneResponse(ctx, clientMessageId, searchResult.getResultCode());
            pool.releaseConnection(conn);
        } else {
            logger.error("Search failed for messageId {}: {}, diagnostic: {}",
                    clientMessageId, searchResult.getResultCode(), searchResult.getDiagnosticMessage());
            LdapUtils.sendSearchDoneResponse(ctx, clientMessageId, searchResult.getResultCode());
            pool.releaseDefunctConnection(conn);
        }
    }

}
