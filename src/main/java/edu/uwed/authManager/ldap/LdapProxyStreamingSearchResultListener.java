package edu.uwed.authManager.ldap;

import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.SearchResultEntryProtocolOp;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultListener;
import com.unboundid.ldap.sdk.SearchResultReference;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Predicate;

public class LdapProxyStreamingSearchResultListener implements SearchResultListener {
    private final ChannelHandlerContext ctx;
    private final Predicate<SearchResultEntry> filter;
    private final BiFunction<SearchResultEntry, Integer, LDAPMessage> entryProcessor;
    private final int serverMessageId;

    public LdapProxyStreamingSearchResultListener(
            ChannelHandlerContext ctx,
            Predicate<SearchResultEntry> filter,
            BiFunction<SearchResultEntry, Integer, LDAPMessage> entryProcessor,
            int serverMessageId
    ) {
        this.ctx = ctx;
        this.filter = filter;
        this.entryProcessor = entryProcessor;
        this.serverMessageId = serverMessageId;
    }

    @Override
    public void searchEntryReturned(SearchResultEntry searchEntry) {
        if (filter.test(searchEntry)) {
            LDAPMessage message = entryProcessor.apply(searchEntry, serverMessageId);
            ByteBuf buf = ctx.alloc().buffer();
            buf.writeBytes(message.encode().encode());
            ctx.writeAndFlush(buf);
        }
    }

    // Другие методы SearchResultListener
    @Override
    public void searchReferenceReturned(SearchResultReference searchReference) {
        // Обработка реферралов, если нужно
    }
}
