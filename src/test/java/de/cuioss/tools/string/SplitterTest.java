/*
 * Copyright 2023 the original author or authors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.tools.string;

import static de.cuioss.tools.collect.CollectionLiterals.immutableList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * Initially taken from
 * <a href="https://github.com/google/guava/blob/master/guava-tests/test/com/google/common/base/SplitterTest.java">...</a>
 */
class SplitterTest {

    private static final Splitter COMMA_SPLITTER = Splitter.on(",");

    @Test
    void testSplitNullString() {
        assertTrue(COMMA_SPLITTER.splitToList(null).isEmpty());
    }

    @Test
    void testCharacterSimpleSplitToList() {
        final var simple = "a,b,c";
        final var letters = COMMA_SPLITTER.splitToList(simple);
        assertEquals(immutableList("a", "b", "c"), letters);
    }

    @Test
    void testCharacterBlankSplitToList() {
        final var simple = "a b c";
        final var letters = Splitter.on(' ').splitToList(simple);
        assertEquals(immutableList("a", "b", "c"), letters);
    }

    @Test
    void testCharacterSimpleSplitWithNoDelimiter() {
        final var simple = "a,b,c";
        final Iterable<String> letters = Splitter.on('.').splitToList(simple);
        assertEquals(immutableList("a,b,c"), letters);
    }

    @Test
    void testCharacterSplitWithDoubleDelimiter() {
        final var doubled = "a,,b,c";
        final Iterable<String> letters = COMMA_SPLITTER.splitToList(doubled);
        assertEquals(immutableList("a", "", "b", "c"), letters);
    }

    @Test
    void testCharacterSplitWithDoubleDelimiterAndSpace() {
        final var doubled = "a,, b,c";
        final Iterable<String> letters = COMMA_SPLITTER.splitToList(doubled);
        assertEquals(immutableList("a", "", " b", "c"), letters);
    }

    @Test
    void testCharacterSplitWithLeadingDelimiter() {
        final var leading = ",a,b,c";
        final Iterable<String> letters = COMMA_SPLITTER.splitToList(leading);
        assertEquals(immutableList("", "a", "b", "c"), letters);
    }

    @Test
    void testCharacterSplitWithMultipleLetters() {
        final Iterable<String> testCharacteringMotto = Splitter.on('-').splitToList("Testing-rocks-Debugging-sucks");
        assertEquals(immutableList("Testing", "rocks", "Debugging", "sucks"), testCharacteringMotto);
    }

    @Test
    void testCharacterSplitWithDoubleDelimiterOmitEmptyStrings() {
        final var doubled = "a..b.c";
        final Iterable<String> letters = Splitter.on('.').omitEmptyStrings().splitToList(doubled);
        assertEquals(immutableList("a", "b", "c"), letters);
    }

    @Test
    void testCharacterSplitEmptyToken() {
        final var emptyToken = "a. .c";
        final Iterable<String> letters = Splitter.on('.').trimResults().splitToList(emptyToken);
        assertEquals(immutableList("a", "", "c"), letters);
    }

    @Test
    void testCharacterSplitEmptyTokenOmitEmptyStrings() {
        final var emptyToken = "a. .c";
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
        final var doubled = "a..b.c";
        final Iterable<String> letters = Splitter.on(".").omitEmptyStrings().splitToList(doubled);
        assertEquals(immutableList("a", "b", "c"), letters);
    }

    @Test
    void testStringSplitEmptyToken() {
        final var emptyToken = "a. .c";
        final Iterable<String> letters = Splitter.on(".").trimResults().splitToList(emptyToken);
        assertEquals(immutableList("a", "", "c"), letters);
    }

    @Test
    void testStringSplitEmptyTokenOmitEmptyStrings() {
        final var emptyToken = "a. .c";
        final Iterable<String> letters = Splitter.on(".").omitEmptyStrings().trimResults().splitToList(emptyToken);
        assertEquals(immutableList("a", "c"), letters);
    }

    @Test
    void testStringSplitWithLongDelimiter() {
        final var longDelimiter = "a, b, c";
        final Iterable<String> letters = Splitter.on(", ").splitToList(longDelimiter);
        assertEquals(immutableList("a", "b", "c"), letters);
    }

    @Test
    void testStringSplitWithLongLeadingDelimiter() {
        final var longDelimiter = ", a, b, c";
        final Iterable<String> letters = Splitter.on(", ").splitToList(longDelimiter);
        assertEquals(immutableList("", "a", "b", "c"), letters);
    }

    @Test
    void testStringSplitWithDelimiterSubstringInValue() {
        final var fourCommasAndFourSpaces = ",,,,    ";
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
        final var simple = "a,b,c,d";
        final Iterable<String> items = COMMA_SPLITTER.limit(1).splitToList(simple);
        assertEquals(immutableList("a,b,c,d"), items);
    }

    @Test
    void testLimitSeparator() {
        final var simple = "a,b,c,d";
        final Iterable<String> items = COMMA_SPLITTER.limit(2).splitToList(simple);
        assertEquals(immutableList("a", "b,c,d"), items);
    }

    @Test
    void testLimitExtraSeparators() {
        final var text = "a,,,b,,c,d";
        final Iterable<String> items = COMMA_SPLITTER.limit(2).splitToList(text);
        assertEquals(immutableList("a", ",,b,,c,d"), items);
    }

    @Test
    void testLimitExtraSeparatorsTrim1NoOmit() {
        final var text = ",,a,,  , b ,, c,d ";
        final Iterable<String> items = COMMA_SPLITTER.limit(1).trimResults().splitToList(text);
        assertEquals(immutableList(",,a,,  , b ,, c,d"), items);
    }

    @Test
    void testLimitExtraSeparatorsTrim1Empty() {
        final var text = "";
        assertTrue(COMMA_SPLITTER.limit(1).splitToList(text).isEmpty());
    }

    @Test
    void testLimitExtraSeparatorsTrim1EmptyOmit() {
        final var text = "";
        final var items = COMMA_SPLITTER.omitEmptyStrings().limit(1).splitToList(text);
        assertTrue(items.isEmpty());
    }

    @Test
    void testInvalidZeroLimit() {
        assertThrows(IllegalArgumentException.class, () -> COMMA_SPLITTER.limit(0));
    }

    @Test
    void shouldMaskSpecialRegularCharacters() {
        // String: .$|()[{^?*+\
        List<String> character = immutableList("[", "]", "{", "}", ".", "*", "+", "(", ")", "$", "|", "^", "?", "\\",
                "<", ">");
        List<String> elements = immutableList("One", "Two", "Three");

        for (String special : character) {
            var template = String.join(special, elements);
            var splitted = Splitter.on(special).splitToList(template);
            assertEquals(elements, splitted);
        }

        var splitter = Splitter.on("[").doNotModifySeparatorString();
        assertThrows(IllegalArgumentException.class, () -> {
            splitter.splitToList("[boom]");
        });
    }
}
