package io.cui.util.string;

import static io.cui.util.collect.CollectionLiterals.immutableList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * Initially taken from
 * https://github.com/google/guava/blob/master/guava-tests/test/com/google/common/base/SplitterTest.java
 */
class SplitterTest {

    private static final Splitter COMMA_SPLITTER = Splitter.on(",");

    @Test
    void testSplitNullString() {
        assertTrue(COMMA_SPLITTER.splitToList(null).isEmpty());
    }

    @Test
    void testCharacterSimpleSplitToList() {
        final String simple = "a,b,c";
        final List<String> letters = COMMA_SPLITTER.splitToList(simple);
        assertEquals(immutableList("a", "b", "c"), letters);
    }

    @Test
    void testCharacterBlankSplitToList() {
        final String simple = "a b c";
        final List<String> letters = Splitter.on(' ').splitToList(simple);
        assertEquals(immutableList("a", "b", "c"), letters);
    }

    @Test
    void testCharacterSimpleSplitWithNoDelimiter() {
        final String simple = "a,b,c";
        final Iterable<String> letters = Splitter.on('.').splitToList(simple);
        assertEquals(immutableList("a,b,c"), letters);
    }

    @Test
    void testCharacterSplitWithDoubleDelimiter() {
        final String doubled = "a,,b,c";
        final Iterable<String> letters = COMMA_SPLITTER.splitToList(doubled);
        assertEquals(immutableList("a", "", "b", "c"), letters);
    }

    @Test
    void testCharacterSplitWithDoubleDelimiterAndSpace() {
        final String doubled = "a,, b,c";
        final Iterable<String> letters = COMMA_SPLITTER.splitToList(doubled);
        assertEquals(immutableList("a", "", " b", "c"), letters);
    }

    @Test
    void testCharacterSplitWithLeadingDelimiter() {
        final String leading = ",a,b,c";
        final Iterable<String> letters = COMMA_SPLITTER.splitToList(leading);
        assertEquals(immutableList("", "a", "b", "c"), letters);
    }

    @Test
    void testCharacterSplitWithMultipleLetters() {
        final Iterable<String> testCharacteringMotto =
            Splitter.on('-').splitToList("Testing-rocks-Debugging-sucks");
        assertEquals(immutableList("Testing", "rocks", "Debugging", "sucks"), testCharacteringMotto);
    }

    @Test
    void testCharacterSplitWithDoubleDelimiterOmitEmptyStrings() {
        final String doubled = "a..b.c";
        final Iterable<String> letters = Splitter.on('.').omitEmptyStrings().splitToList(doubled);
        assertEquals(immutableList("a", "b", "c"), letters);
    }

    @Test
    void testCharacterSplitEmptyToken() {
        final String emptyToken = "a. .c";
        final Iterable<String> letters = Splitter.on('.').trimResults().splitToList(emptyToken);
        assertEquals(immutableList("a", "", "c"), letters);
    }

    @Test
    void testCharacterSplitEmptyTokenOmitEmptyStrings() {
        final String emptyToken = "a. .c";
        final Iterable<String> letters = Splitter.on('.').omitEmptyStrings().trimResults().splitToList(emptyToken);
        assertEquals(immutableList("a", "c"), letters);
    }

    @Test
    void testCharacterSplitOnEmptyString() {
        assertTrue(Splitter.on('.').splitToList("").isEmpty());
    }

    @Test
    void testCharacterSplitOnEmptyStringOmitEmptyStrings() {
        assertTrue(Splitter.on('.').omitEmptyStrings().splitToList("").isEmpty());
    }

    @Test
    void testCharacterSplitOnOnlyDelimiter() {
        assertTrue(Splitter.on('.').splitToList(".").isEmpty());
    }

    @Test
    void testCharacterSplitOnOnlyDelimitersOmitEmptyStrings() {
        assertTrue(Splitter.on('.').omitEmptyStrings().splitToList("...").isEmpty());
    }

    @Test
    void testStringSplitWithDoubleDelimiterOmitEmptyStrings() {
        final String doubled = "a..b.c";
        final Iterable<String> letters = Splitter.on(".").omitEmptyStrings().splitToList(doubled);
        assertEquals(immutableList("a", "b", "c"), letters);
    }

    @Test
    void testStringSplitEmptyToken() {
        final String emptyToken = "a. .c";
        final Iterable<String> letters = Splitter.on(".").trimResults().splitToList(emptyToken);
        assertEquals(immutableList("a", "", "c"), letters);
    }

    @Test
    void testStringSplitEmptyTokenOmitEmptyStrings() {
        final String emptyToken = "a. .c";
        final Iterable<String> letters = Splitter.on(".").omitEmptyStrings().trimResults().splitToList(emptyToken);
        assertEquals(immutableList("a", "c"), letters);
    }

    @Test
    void testStringSplitWithLongDelimiter() {
        final String longDelimiter = "a, b, c";
        final Iterable<String> letters = Splitter.on(", ").splitToList(longDelimiter);
        assertEquals(immutableList("a", "b", "c"), letters);
    }

    @Test
    void testStringSplitWithLongLeadingDelimiter() {
        final String longDelimiter = ", a, b, c";
        final Iterable<String> letters = Splitter.on(", ").splitToList(longDelimiter);
        assertEquals(immutableList("", "a", "b", "c"), letters);
    }

    @Test
    void testStringSplitWithDelimiterSubstringInValue() {
        final String fourCommasAndFourSpaces = ",,,,    ";
        final Iterable<String> threeCommasThenThreeSpaces = Splitter.on(", ").splitToList(fourCommasAndFourSpaces);
        assertEquals(immutableList(",,,", "   "), threeCommasThenThreeSpaces);
    }

    @Test
    void testStringSplitWithEmptyString() {
        try {
            Splitter.on("");
            fail();
        } catch (final IllegalArgumentException expected) {
        }
    }

    @Test
    void testLimit1Separator() {
        final String simple = "a,b,c,d";
        final Iterable<String> items = COMMA_SPLITTER.limit(1).splitToList(simple);
        assertEquals(immutableList("a,b,c,d"), items);
    }

    @Test
    void testLimitSeparator() {
        final String simple = "a,b,c,d";
        final Iterable<String> items = COMMA_SPLITTER.limit(2).splitToList(simple);
        assertEquals(immutableList("a", "b,c,d"), items);
    }

    @Test
    void testLimitExtraSeparators() {
        final String text = "a,,,b,,c,d";
        final Iterable<String> items = COMMA_SPLITTER.limit(2).splitToList(text);
        assertEquals(immutableList("a", ",,b,,c,d"), items);
    }

    @Test
    void testLimitExtraSeparatorsTrim1NoOmit() {
        final String text = ",,a,,  , b ,, c,d ";
        final Iterable<String> items = COMMA_SPLITTER.limit(1).trimResults().splitToList(text);
        assertEquals(immutableList(",,a,,  , b ,, c,d"), items);
    }

    @Test
    void testLimitExtraSeparatorsTrim1Empty() {
        final String text = "";
        assertTrue(COMMA_SPLITTER.limit(1).splitToList(text).isEmpty());
    }

    @Test
    void testLimitExtraSeparatorsTrim1EmptyOmit() {
        final String text = "";
        final List<String> items = COMMA_SPLITTER.omitEmptyStrings().limit(1).splitToList(text);
        assertTrue(items.isEmpty());
    }

    @Test
    void testInvalidZeroLimit() {
        assertThrows(IllegalArgumentException.class, () -> COMMA_SPLITTER.limit(0));
    }

    @Test
    void shouldMaskSpecialRegularCharacters() {
        // String: .$|()[{^?*+\
        List<String> character =
            immutableList("[", "]", "{", "}", ".", "*", "+", "(", ")", "$", "|", "^", "?", "\\", "<", ">");
        List<String> elements = immutableList("One", "Two", "Three");

        for (String special : character) {
            String template = String.join(special, elements);
            List<String> splitted = Splitter.on(special).splitToList(template);
            assertEquals(elements, splitted);
        }

        Splitter splitter = Splitter.on("[").doNotModifySeparatorString();
        assertThrows(IllegalArgumentException.class,
                () -> {
                    splitter.splitToList("[boom]");
                });
    }
}
