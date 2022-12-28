package io.cui.tools.string;

import static io.cui.tools.collect.CollectionLiterals.immutableList;
import static io.cui.tools.string.MoreStrings.emptyToNull;
import static io.cui.tools.string.MoreStrings.nullToEmpty;
import static io.cui.tools.string.MoreStrings.unquote;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

class MoreStringsTest {

    private static final String MESSAGE = "Message";
    private static final String NON_EMPTY_STRING = "a";
    private static final List<String> QUOTED_STRINGS = immutableList("\"\"", "\"abc\"", "''", "'abc'");
    private static final List<String> NOT_QUOTED_STRINGS = immutableList("\"\'", "\'abc\"", "'\"", "\"abc'");

    private static final String WHITESPACE;
    private static final String NON_WHITESPACE;

    static {
        String ws = "";
        String nws = "";
        for (int i = 0; i < Character.MAX_VALUE; i++) {
            if (Character.isWhitespace((char) i)) {
                ws += String.valueOf((char) i);
                if (i > 32) {
                }
            } else if (i < 40) {
                nws += String.valueOf((char) i);
            }
        }
        for (int i = 0; i <= 32; i++) {
        }
        WHITESPACE = ws;
        NON_WHITESPACE = nws;
    }

    @Test
    void shouldQuote() {
        assertNull(unquote(null));
        assertEquals("", unquote(""));
        for (final String quote : QUOTED_STRINGS) {
            assertEquals(quote.substring(1, quote.length() - 1), unquote(quote));
        }
        for (final String notQuoted : NOT_QUOTED_STRINGS) {
            assertEquals(notQuoted, unquote(notQuoted));
        }
    }

    /**
     * Test for {@link MoreStrings#isAllLowerCase(CharSequence)}.
     * COPIED FROM:
     * https://github.com/apache/commons-lang/blob/LANG_3_8_1/src/test/java/org/apache/commons/lang3/MoreStringsTest.java
     */
    @Test
    void testIsAllLowerCase() {
        assertFalse(MoreStrings.isAllLowerCase(null));
        assertFalse(MoreStrings.isAllLowerCase(MoreStrings.EMPTY));
        assertFalse(MoreStrings.isAllLowerCase("  "));
        assertTrue(MoreStrings.isAllLowerCase("abc"));
        assertFalse(MoreStrings.isAllLowerCase("abc "));
        assertFalse(MoreStrings.isAllLowerCase("abc\n"));
        assertFalse(MoreStrings.isAllLowerCase("abC"));
        assertFalse(MoreStrings.isAllLowerCase("ab c"));
        assertFalse(MoreStrings.isAllLowerCase("ab1c"));
        assertFalse(MoreStrings.isAllLowerCase("ab/c"));
    }

    /**
     * Test for {@link MoreStrings#isAllUpperCase(CharSequence)}.
     * COPIED FROM:
     * https://github.com/apache/commons-lang/blob/LANG_3_8_1/src/test/java/org/apache/commons/lang3/MoreStringsTest.java
     */
    @Test
    void testIsAllUpperCase() {
        assertFalse(MoreStrings.isAllUpperCase(null));
        assertFalse(MoreStrings.isAllUpperCase(MoreStrings.EMPTY));
        assertFalse(MoreStrings.isAllUpperCase("  "));
        assertTrue(MoreStrings.isAllUpperCase("ABC"));
        assertFalse(MoreStrings.isAllUpperCase("ABC "));
        assertFalse(MoreStrings.isAllUpperCase("ABC\n"));
        assertFalse(MoreStrings.isAllUpperCase("aBC"));
        assertFalse(MoreStrings.isAllUpperCase("A C"));
        assertFalse(MoreStrings.isAllUpperCase("A1C"));
        assertFalse(MoreStrings.isAllUpperCase("A/C"));
    }

    /**
     * COPIED FROM:
     * https://github.com/apache/commons-lang/blob/LANG_3_8_1/src/test/java/org/apache/commons/lang3/MoreStringsIsTest.java
     */
    @Test
    void testIsNumeric() {
        assertFalse(MoreStrings.isNumeric(null));
        assertFalse(MoreStrings.isNumeric(""));
        assertFalse(MoreStrings.isNumeric(" "));
        assertFalse(MoreStrings.isNumeric(NON_EMPTY_STRING));
        assertFalse(MoreStrings.isNumeric("A"));
        assertFalse(MoreStrings.isNumeric("kgKgKgKgkgkGkjkjlJlOKLgHdGdHgl"));
        assertFalse(MoreStrings.isNumeric("ham kso"));
        assertTrue(MoreStrings.isNumeric("1"));
        assertTrue(MoreStrings.isNumeric("1000"));
        assertTrue(MoreStrings.isNumeric("\u0967\u0968\u0969"));
        assertFalse(MoreStrings.isNumeric("\u0967\u0968 \u0969"));
        assertFalse(MoreStrings.isNumeric("2.3"));
        assertFalse(MoreStrings.isNumeric("10 00"));
        assertFalse(MoreStrings.isNumeric("hkHKHik6iUGHKJgU7tUJgKJGI87GIkug"));
        assertFalse(MoreStrings.isNumeric("_"));
        assertFalse(MoreStrings.isNumeric("hkHKHik*khbkuh"));
        assertFalse(MoreStrings.isNumeric("+123"));
        assertFalse(MoreStrings.isNumeric("-123"));
    }

    /**
     * COPIED FROM:
     * https://github.com/apache/commons-lang/blob/LANG_3_8_1/src/test/java/org/apache/commons/lang3/MoreStringsEmptyBlankTest.java
     */
    @Test
    void testIsEmpty() {
        assertTrue(MoreStrings.isEmpty(null));
        assertTrue(MoreStrings.isEmpty(""));
        assertFalse(MoreStrings.isEmpty(" "));
        assertFalse(MoreStrings.isEmpty("foo"));
        assertFalse(MoreStrings.isEmpty("  foo  "));
    }

    /**
     * COPIED FROM:
     * https://github.com/apache/commons-lang/blob/LANG_3_8_1/src/test/java/org/apache/commons/lang3/MoreStringsEmptyBlankTest.java
     */
    @Test
    void testIsBlank() {
        assertTrue(MoreStrings.isBlank(null));
        assertTrue(MoreStrings.isBlank(""));
        assertTrue(MoreStrings.isBlank(WHITESPACE));
        assertFalse(MoreStrings.isBlank("foo"));
        assertFalse(MoreStrings.isBlank("  foo  "));
    }

    @Test
    void testCountMatches_String() {
        assertEquals(0, MoreStrings.countMatches(null, null));
        assertEquals(0, MoreStrings.countMatches("blah", null));
        assertEquals(0, MoreStrings.countMatches(null, "DD"));

        assertEquals(0, MoreStrings.countMatches("x", ""));
        assertEquals(0, MoreStrings.countMatches("", ""));

        assertEquals(3, MoreStrings.countMatches("one long someone sentence of one", "one"));
        assertEquals(0, MoreStrings.countMatches("one long someone sentence of one", "two"));
        assertEquals(4, MoreStrings.countMatches("oooooooooooo", "ooo"));
    }

    @Test
    void testLeftPad_StringIntChar() {
        assertNull(MoreStrings.leftPad(null, 5, ' '));
        assertEquals("     ", MoreStrings.leftPad("", 5, ' '));
        assertEquals("  abc", MoreStrings.leftPad("abc", 5, ' '));
        assertEquals("xxabc", MoreStrings.leftPad("abc", 5, 'x'));
        assertEquals("\uffff\uffffabc", MoreStrings.leftPad("abc", 5, '\uffff'));
        assertEquals("abc", MoreStrings.leftPad("abc", 2, ' '));
        final String str = MoreStrings.leftPad("aaa", 10000, 'a'); // bigger than pad length
        assertEquals(10000, str.length());
    }

    @Test
    void testLeftPad_StringIntString() {
        assertNull(MoreStrings.leftPad(null, 5, "-+"));
        assertNull(MoreStrings.leftPad(null, 5, null));
        assertEquals("     ", MoreStrings.leftPad("", 5, " "));
        assertEquals("-+-+abc", MoreStrings.leftPad("abc", 7, "-+"));
        assertEquals("-+~abc", MoreStrings.leftPad("abc", 6, "-+~"));
        assertEquals("-+abc", MoreStrings.leftPad("abc", 5, "-+~"));
        assertEquals("abc", MoreStrings.leftPad("abc", 2, " "));
        assertEquals("abc", MoreStrings.leftPad("abc", -1, " "));
        assertEquals("  abc", MoreStrings.leftPad("abc", 5, null));
        assertEquals("  abc", MoreStrings.leftPad("abc", 5, ""));
    }

    @Test
    void testRepeat_CharInt() {
        assertEquals("zzz", MoreStrings.repeat('z', 3));
        assertEquals("", MoreStrings.repeat('z', 0));
        assertEquals("", MoreStrings.repeat('z', -2));
    }

    @Test
    void testIndexOf_StringInt() {
        assertEquals(-1, MoreStrings.indexOf(null, null, 0));
        assertEquals(-1, MoreStrings.indexOf(null, null, -1));
        assertEquals(-1, MoreStrings.indexOf(null, "", 0));
        assertEquals(-1, MoreStrings.indexOf(null, "", -1));
        assertEquals(-1, MoreStrings.indexOf("", null, 0));
        assertEquals(-1, MoreStrings.indexOf("", null, -1));
        assertEquals(0, MoreStrings.indexOf("", "", 0));
        assertEquals(0, MoreStrings.indexOf("", "", -1));
        assertEquals(0, MoreStrings.indexOf("", "", 9));
        assertEquals(0, MoreStrings.indexOf("abc", "", 0));
        assertEquals(0, MoreStrings.indexOf("abc", "", -1));
        assertEquals(3, MoreStrings.indexOf("abc", "", 9));
        assertEquals(3, MoreStrings.indexOf("abc", "", 3));
        assertEquals(0, MoreStrings.indexOf("aabaabaa", NON_EMPTY_STRING, 0));
        assertEquals(2, MoreStrings.indexOf("aabaabaa", "b", 0));
        assertEquals(1, MoreStrings.indexOf("aabaabaa", "ab", 0));
        assertEquals(5, MoreStrings.indexOf("aabaabaa", "b", 3));
        assertEquals(-1, MoreStrings.indexOf("aabaabaa", "b", 9));
        assertEquals(2, MoreStrings.indexOf("aabaabaa", "b", -1));
        assertEquals(2, MoreStrings.indexOf("aabaabaa", "", 2));

        // Test that startIndex works correctly, i.e. cannot match before startIndex
        assertEquals(7, MoreStrings.indexOf("12345678", "8", 5));
        assertEquals(7, MoreStrings.indexOf("12345678", "8", 6));
        assertEquals(7, MoreStrings.indexOf("12345678", "8", 7)); // 7 is last index
        assertEquals(-1, MoreStrings.indexOf("12345678", "8", 8));

        assertEquals(5, MoreStrings.indexOf(new StringBuilder("aabaabaa"), "b", 3));
    }

    @Test
    void testLANG666() {
        assertEquals("12", MoreStrings.stripEnd("120.00", ".0"));
        assertEquals("121", MoreStrings.stripEnd("121.00", ".0"));
    }

    @Test
    void testStripEnd_StringString() {
        // null stripEnd
        assertNull(MoreStrings.stripEnd(null, null));
        assertEquals("", MoreStrings.stripEnd("", null));
        assertEquals("", MoreStrings.stripEnd("        ", null));
        assertEquals("  abc", MoreStrings.stripEnd("  abc  ", null));
        assertEquals(MoreStringsTest.WHITESPACE + MoreStringsTest.NON_WHITESPACE,
                MoreStrings.stripEnd(
                        MoreStringsTest.WHITESPACE + MoreStringsTest.NON_WHITESPACE + MoreStringsTest.WHITESPACE,
                        null));

        // "" stripEnd
        assertNull(MoreStrings.stripEnd(null, ""));
        assertEquals("", MoreStrings.stripEnd("", ""));
        assertEquals("        ", MoreStrings.stripEnd("        ", ""));
        assertEquals("  abc  ", MoreStrings.stripEnd("  abc  ", ""));
        assertEquals(MoreStringsTest.WHITESPACE, MoreStrings.stripEnd(MoreStringsTest.WHITESPACE, ""));

        // " " stripEnd
        assertNull(MoreStrings.stripEnd(null, " "));
        assertEquals("", MoreStrings.stripEnd("", " "));
        assertEquals("", MoreStrings.stripEnd("        ", " "));
        assertEquals("  abc", MoreStrings.stripEnd("  abc  ", " "));

        // "ab" stripEnd
        assertNull(MoreStrings.stripEnd(null, "ab"));
        assertEquals("", MoreStrings.stripEnd("", "ab"));
        assertEquals("        ", MoreStrings.stripEnd("        ", "ab"));
        assertEquals("  abc  ", MoreStrings.stripEnd("  abc  ", "ab"));
        assertEquals("abc", MoreStrings.stripEnd("abcabab", "ab"));
        assertEquals(MoreStringsTest.WHITESPACE, MoreStrings.stripEnd(MoreStringsTest.WHITESPACE, ""));
    }

    @Test
    void testNonWhitespaceChar() {
        assertFalse(MoreStrings.hasNonWhitespaceChar(null));
        assertFalse(MoreStrings.hasNonWhitespaceChar(""));
        assertFalse(MoreStrings.hasNonWhitespaceChar(" "));
        assertFalse(MoreStrings.hasNonWhitespaceChar("    "));
        assertFalse(MoreStrings.hasNonWhitespaceChar(WHITESPACE));
        assertTrue(MoreStrings.hasNonWhitespaceChar(NON_WHITESPACE));
        assertTrue(MoreStrings.hasNonWhitespaceChar(WHITESPACE + NON_WHITESPACE + WHITESPACE));
        assertTrue(MoreStrings.hasNonWhitespaceChar(NON_EMPTY_STRING));
        assertTrue(MoreStrings.hasNonWhitespaceChar(" a "));
    }

    @Test
    @SuppressWarnings("squid:S2699") // owolff: No assertions necessary -> will throw exceptions
    void shouldDeterminesEmptyStringPassthrough() {
        // Positive / Passthrough cases
        MoreStrings.requireNotEmpty(NON_EMPTY_STRING);
        MoreStrings.requireNotEmpty(NON_EMPTY_STRING, MESSAGE);

        MoreStrings.requireNotEmptyTrimmed(NON_EMPTY_STRING);
        MoreStrings.requireNotEmptyTrimmed(NON_EMPTY_STRING, MESSAGE);
    }

    @Test
    void shouldDeterminesEmptyString() {
        assertThrows(IllegalArgumentException.class, () -> {
            MoreStrings.requireNotEmpty("");
        });
        assertThrows(IllegalArgumentException.class, () -> {
            MoreStrings.requireNotEmpty("", MESSAGE);
        });

        assertThrows(IllegalArgumentException.class, () -> {
            MoreStrings.requireNotEmptyTrimmed("");
        });
        assertThrows(IllegalArgumentException.class, () -> {
            MoreStrings.requireNotEmptyTrimmed("", MESSAGE);
        });
        assertThrows(IllegalArgumentException.class, () -> {
            MoreStrings.requireNotEmptyTrimmed(" ");
        });
        assertThrows(IllegalArgumentException.class, () -> {
            MoreStrings.requireNotEmptyTrimmed(" ", MESSAGE);
        });
    }

    @Test
    void shouldHandleNullStringToEmpty() {
        assertEquals(NON_EMPTY_STRING, nullToEmpty(NON_EMPTY_STRING));
        assertEquals("", nullToEmpty(null));
        assertEquals("", nullToEmpty(""));
        assertEquals(" ", nullToEmpty(" "), "Must not trim");
    }

    @Test
    void shouldHandleEmptyStringToNull() {
        assertEquals(NON_EMPTY_STRING, emptyToNull(NON_EMPTY_STRING));
        assertNull(emptyToNull(null));
        assertNull(emptyToNull(""));
        assertEquals(" ", emptyToNull(" "), "Must not trim");
    }

    @Test
    void nullSafeTrimming() {
        assertNull(MoreStrings.trimOrNull(null));
        assertEquals("", MoreStrings.trimOrNull(""));
        assertEquals("", MoreStrings.trimOrNull("   "));
        assertEquals("x", MoreStrings.trimOrNull(" x "));
    }

    @Test
    void testLenientFormat() {
        assertEquals("%s", MoreStrings.lenientFormat("%s"));
        assertEquals("5", MoreStrings.lenientFormat("%s", 5));
        assertEquals("foo [5]", MoreStrings.lenientFormat("foo", 5));
        assertEquals("foo [5, 6, 7]", MoreStrings.lenientFormat("foo", 5, 6, 7));
        assertEquals("%s 1 2", MoreStrings.lenientFormat("%s %s %s", "%s", 1, 2));
        assertEquals(" [5, 6]", MoreStrings.lenientFormat("", 5, 6));
        assertEquals("123", MoreStrings.lenientFormat("%s%s%s", 1, 2, 3));
        assertEquals("1%s%s", MoreStrings.lenientFormat("%s%s%s", 1));
        assertEquals("5 + 6 = 11", MoreStrings.lenientFormat("%s + 6 = 11", 5));
        assertEquals("5 + 6 = 11", MoreStrings.lenientFormat("5 + %s = 11", 6));
        assertEquals("5 + 6 = 11", MoreStrings.lenientFormat("5 + 6 = %s", 11));
        assertEquals("5 + 6 = 11", MoreStrings.lenientFormat("%s + %s = %s", 5, 6, 11));
        assertEquals("null [null, null]", MoreStrings.lenientFormat("%s", null, null, null));
        assertEquals("null [5, 6]", MoreStrings.lenientFormat(null, 5, 6));
        assertEquals("null", MoreStrings.lenientFormat("%s", (Object) null));
        assertEquals("(Object[])null", MoreStrings.lenientFormat("%s", (Object[]) null));
    }

    @Test
    void testLenientFormat_badArgumentToString() {

        String lenientFormat = MoreStrings.lenientFormat("boiler %s plate", new ThrowsOnToString());
        assertTrue(lenientFormat.startsWith("boiler <io.cui.tools.string.MoreStringsTest"));
        assertTrue(lenientFormat.endsWith("threw java.lang.UnsupportedOperationException> plate"));
    }

    @Test
    void returnsFirstNonEmpty() {
        assertEquals(" ", MoreStrings.firstNonEmpty(null, "", " ", "b", "a").orElseThrow());
    }

    @Test
    void returnsFirstNonBlank() {
        assertEquals("b", MoreStrings.firstNonBlank(null, "", " ", "b", "a").orElseThrow());
    }

    private static class ThrowsOnToString {

        @Override
        public String toString() {
            throw new UnsupportedOperationException();
        }
    }
}
