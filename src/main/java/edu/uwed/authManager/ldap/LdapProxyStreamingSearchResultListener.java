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
    private static final Logger logger = LoggerFactory.getLogger(LdapProxyStreamingSearchResultListener.class);

    private final ChannelHandlerContext ctx;
    private final int messageID;
    private final Predicate<SearchResultEntry> filter; // Фильтр в виде предикат
    private final BiFunction<SearchResultEntry, Integer, LDAPMessage> entryProcessor; // Функция-обработчик

    public LdapProxyStreamingSearchResultListener(
            ChannelHandlerContext ctx,
            Predicate<SearchResultEntry> filter,
            BiFunction<SearchResultEntry, Integer, LDAPMessage> entryProcessor,
            int messageID
            ) {
        this.ctx = ctx;
        this.messageID = messageID;
        this.filter = filter;
        this.entryProcessor = entryProcessor;
    }

    @Override
    public void searchEntryReturned(SearchResultEntry searchResultEntry) {
        try {
            if (filter.test(searchResultEntry)) {
                logger.info("Processing entry with DN: {}", searchResultEntry.getDN());

                // Создаем LDAPMessage
                LDAPMessage entryMessage;
                if (entryProcessor != null) {
                    // Если функция-обработчик передана, используем её
                    entryMessage = entryProcessor.apply(searchResultEntry,messageID);
                } else {
                    // Если функция не передана, создаем LDAPMessage из исходной записи
                    SearchResultEntryProtocolOp entryOp = new SearchResultEntryProtocolOp(searchResultEntry);
                    entryMessage = new LDAPMessage(messageID, entryOp);
                }

                // Кодируем LDAPMessage в ASN.1
                byte[] asn1Bytes = entryMessage.encode().encode();

                // Создаем ByteBuf и записываем в него закодированный результат
                ByteBuf responseBuf = ctx.alloc().buffer(asn1Bytes.length);
                responseBuf.writeBytes(asn1Bytes);

                // Отправляем результат в Netty-канал
                ctx.writeAndFlush(responseBuf);

                logger.info("Sent LDAP entry to Netty channel: {}", searchResultEntry.getDN());
            } else {
                logger.debug("Entry with DN: {} did not pass filter", searchResultEntry.getDN());
            }
        } catch (Exception e) {
            logger.error("Failed to process or send LDAP entry with DN: {}", searchResultEntry.getDN(), e);
        }
    }

    @Override
    public void searchReferenceReturned(SearchResultReference searchResultReference) {
        logger.debug("Received search reference: {}", (Object) searchResultReference.getReferralURLs());
    }
}
