package de.icw.util.primitives;

import static de.icw.util.primitives.MoreStrings.joinNotBlankStrings;
import static de.icw.util.primitives.MoreStrings.unquote;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.google.common.collect.ImmutableList;

class MoreStringsTest {

    private static final List<String> QUOTED_STRINGS = ImmutableList.of("\"\"", "\"abc\"", "''", "'abc'");
    private static final List<String> NOT_QUOTED_STRINGS = ImmutableList.of("\"\'", "\'abc\"", "'\"", "\"abc'");

    @Test
    void shouldQuote() {
        assertNull(unquote(null));
        assertEquals("", unquote(""));
        for (String quote : QUOTED_STRINGS) {
            assertEquals(quote.substring(1, quote.length() - 1), unquote(quote));
        }
        for (String notQuoted : NOT_QUOTED_STRINGS) {
            assertEquals(notQuoted, unquote(notQuoted));
        }
    }

    @Test
    void shouldJoinNotBlank() {
        assertEquals("a b", joinNotBlankStrings(" ", "a", "b", ""));
    }

}
