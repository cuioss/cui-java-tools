/**
 * Copyright © 2025 CUI-OpenSource-Software (info@cuioss.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.tools.string;

import org.junit.jupiter.api.Test;

import java.util.List;

import static de.cuioss.tools.collect.CollectionLiterals.immutableList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Initially taken from
 * <a href="https://github.com/google/guava/blob/master/guava-tests/test/com/google/common/base/SplitterTest.java">...</a>
 */
class SplitterTest {

    private static final Splitter COMMA_SPLITTER = Splitter.on(",");

    @Test
    void splitNullString() {
        assertTrue(COMMA_SPLITTER.splitToList(null).isEmpty());
    }

    @Test
    void characterSimpleSplitToList() {
        final var simple = "a,b,c";
        final var letters = COMMA_SPLITTER.splitToList(simple);
        assertEquals(immutableList("a", "b", "c"), letters);
    }

    @Test
    void characterBlankSplitToList() {
        final var simple = "a b c";
        final var letters = Splitter.on(' ').splitToList(simple);
        assertEquals(immutableList("a", "b", "c"), letters);
    }

    @Test
    void characterSimpleSplitWithNoDelimiter() {
        final var simple = "a,b,c";
        final Iterable<String> letters = Splitter.on('.').splitToList(simple);
        assertEquals(immutableList("a,b,c"), letters);
    }

    @Test
    void characterSplitWithDoubleDelimiter() {
        final var doubled = "a,,b,c";
        final Iterable<String> letters = COMMA_SPLITTER.splitToList(doubled);
        assertEquals(immutableList("a", "", "b", "c"), letters);
    }

    @Test
    void characterSplitWithDoubleDelimiterAndSpace() {
        final var doubled = "a,, b,c";
        final Iterable<String> letters = COMMA_SPLITTER.splitToList(doubled);
        assertEquals(immutableList("a", "", " b", "c"), letters);
    }

    @Test
    void characterSplitWithLeadingDelimiter() {
        final var leading = ",a,b,c";
        final Iterable<String> letters = COMMA_SPLITTER.splitToList(leading);
        assertEquals(immutableList("", "a", "b", "c"), letters);
    }

    @Test
    void characterSplitWithMultipleLetters() {
        final Iterable<String> testCharacteringMotto = Splitter.on('-').splitToList("Testing-rocks-Debugging-sucks");
        assertEquals(immutableList("Testing", "rocks", "Debugging", "sucks"), testCharacteringMotto);
    }

    @Test
    void characterSplitWithDoubleDelimiterOmitEmptyStrings() {
        final var doubled = "a..b.c";
        final Iterable<String> letters = Splitter.on('.').omitEmptyStrings().splitToList(doubled);
        assertEquals(immutableList("a", "b", "c"), letters);
    }

    @Test
    void characterSplitEmptyToken() {
        final var emptyToken = "a. .c";
        final Iterable<String> letters = Splitter.on('.').trimResults().splitToList(emptyToken);
        assertEquals(immutableList("a", "", "c"), letters);
    }

    @Test
    void characterSplitEmptyTokenOmitEmptyStrings() {
        final var emptyToken = "a. .c";
        final Iterable<String> letters = Splitter.on('.').omitEmptyStrings().trimResults().splitToList(emptyToken);
        assertEquals(immutableList("a", "c"), letters);
    }

    @Test
    void characterSplitOnEmptyString() {
        assertTrue(Splitter.on('.').splitToList("").isEmpty());
    }

    @Test
    void characterSplitOnEmptyStringOmitEmptyStrings() {
        assertTrue(Splitter.on('.').omitEmptyStrings().splitToList("").isEmpty());
    }

    @Test
    void characterSplitOnOnlyDelimiter() {
        assertTrue(Splitter.on('.').splitToList(".").isEmpty());
    }

    @Test
    void characterSplitOnOnlyDelimitersOmitEmptyStrings() {
        assertTrue(Splitter.on('.').omitEmptyStrings().splitToList("...").isEmpty());
    }

    @Test
    void stringSplitWithDoubleDelimiterOmitEmptyStrings() {
        final var doubled = "a..b.c";
        final Iterable<String> letters = Splitter.on(".").omitEmptyStrings().splitToList(doubled);
        assertEquals(immutableList("a", "b", "c"), letters);
    }

    @Test
    void stringSplitEmptyToken() {
        final var emptyToken = "a. .c";
        final Iterable<String> letters = Splitter.on(".").trimResults().splitToList(emptyToken);
        assertEquals(immutableList("a", "", "c"), letters);
    }

    @Test
    void stringSplitEmptyTokenOmitEmptyStrings() {
        final var emptyToken = "a. .c";
        final Iterable<String> letters = Splitter.on(".").omitEmptyStrings().trimResults().splitToList(emptyToken);
        assertEquals(immutableList("a", "c"), letters);
    }

    @Test
    void stringSplitWithLongDelimiter() {
        final var longDelimiter = "a, b, c";
        final Iterable<String> letters = Splitter.on(", ").splitToList(longDelimiter);
        assertEquals(immutableList("a", "b", "c"), letters);
    }

    @Test
    void stringSplitWithLongLeadingDelimiter() {
        final var longDelimiter = ", a, b, c";
        final Iterable<String> letters = Splitter.on(", ").splitToList(longDelimiter);
        assertEquals(immutableList("", "a", "b", "c"), letters);
    }

    @Test
    void stringSplitWithDelimiterSubstringInValue() {
        final var fourCommasAndFourSpaces = ",,,,    ";
        final Iterable<String> threeCommasThenThreeSpaces = Splitter.on(", ").splitToList(fourCommasAndFourSpaces);
        assertEquals(immutableList(",,,", "   "), threeCommasThenThreeSpaces);
    }

    @Test
    void stringSplitWithEmptyString() {
        assertThrows(IllegalArgumentException.class, () -> Splitter.on(""));
    }

    @Test
    void limit1Separator() {
        final var simple = "a,b,c,d";
        final Iterable<String> items = COMMA_SPLITTER.limit(1).splitToList(simple);
        assertEquals(immutableList("a,b,c,d"), items);
    }

    @Test
    void limitSeparator() {
        final var simple = "a,b,c,d";
        final Iterable<String> items = COMMA_SPLITTER.limit(2).splitToList(simple);
        assertEquals(immutableList("a", "b,c,d"), items);
    }

    @Test
    void limitExtraSeparators() {
        final var text = "a,,,b,,c,d";
        final Iterable<String> items = COMMA_SPLITTER.limit(2).splitToList(text);
        assertEquals(immutableList("a", ",,b,,c,d"), items);
    }

    @Test
    void limitExtraSeparatorsTrim1NoOmit() {
        final var text = ",,a,,  , b ,, c,d ";
        final Iterable<String> items = COMMA_SPLITTER.limit(1).trimResults().splitToList(text);
        assertEquals(immutableList(",,a,,  , b ,, c,d"), items);
    }

    @Test
    void limitExtraSeparatorsTrim1Empty() {
        final var text = "";
        assertTrue(COMMA_SPLITTER.limit(1).splitToList(text).isEmpty());
    }

    @Test
    void limitExtraSeparatorsTrim1EmptyOmit() {
        final var text = "";
        final var items = COMMA_SPLITTER.omitEmptyStrings().limit(1).splitToList(text);
        assertTrue(items.isEmpty());
    }

    @Test
    void invalidZeroLimit() {
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
        assertThrows(IllegalArgumentException.class, () ->
                splitter.splitToList("[boom]"));
    }

    @Test
    void onCharacterWithNullSeparator() {
        Character nullChar = null;
        assertThrows(NullPointerException.class, () -> {
            Splitter.on(nullChar);
        }, "separator must not be null");
    }
}
