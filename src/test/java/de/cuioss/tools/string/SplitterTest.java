/*
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
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import static de.cuioss.tools.collect.CollectionLiterals.immutableList;
import static org.junit.jupiter.api.Assertions.*;

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
    void shouldHandleNullPatternByQuoting() {
        // This ensures line 298 is covered - when pattern is null, it compiles a quoted separator
        var config = new SplitterConfig.Builder().separator(".").build(); // No pattern set, only separator
        var splitter = new Splitter(config);
        var result = splitter.splitToList("a.b.c");
        assertEquals(3, result.size());
        assertEquals("a", result.getFirst());
        assertEquals("b", result.get(1));
        assertEquals("c", result.get(2));
    }

    @Test
    void shouldHandleNullElementsInResults() {
        // This tests the null element handling in addIfApplicable (line 316)
        var splitter = Splitter.on(",").omitEmptyStrings();
        var result = splitter.splitToList("a,,b"); // Empty string becomes null in some cases
        // The empty element should be omitted, so we get 2 elements
        assertEquals(2, result.size());
        assertEquals("a", result.getFirst());
        assertEquals("b", result.get(1));
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
    }

    @Test
    void doNotModifySeparatorStringShouldTreatSeparatorAsRegex() {
        // With the flag: the separator is used as a raw regex, splitting on ',' and '.'
        var result = Splitter.on("[,.]").doNotModifySeparatorString().splitToList("a,b.c");
        assertEquals(immutableList("a", "b", "c"), result);
    }

    @Test
    void separatorShouldBeTreatedLiterallyWithoutDoNotModifySeparatorString() {
        // Without the flag: the separator is the literal string "[,.]"
        assertEquals(immutableList("a", "b"), Splitter.on("[,.]").splitToList("a[,.]b"));
        assertEquals(immutableList("a,b.c"), Splitter.on("[,.]").splitToList("a,b.c"));
    }

    @Test
    void doNotModifySeparatorStringShouldFailOnInvalidRegex() {
        var splitter = Splitter.on("[");
        assertThrows(PatternSyntaxException.class, splitter::doNotModifySeparatorString);
    }

    @Test
    void shouldHonorFlagsOfUserSuppliedPattern() {
        var pattern = Pattern.compile("a", Pattern.CASE_INSENSITIVE);
        var result = Splitter.on(pattern).splitToList("xAy");
        assertEquals(immutableList("x", "y"), result);
    }

    @Test
    void shouldKeepLeadingButRemoveTrailingEmptyStrings() {
        // String#split limit-0 semantics: trailing empty strings are removed, leading kept
        assertEquals(immutableList("", "a"), COMMA_SPLITTER.splitToList(",a,,"));
    }

    @Test
    void onCharacterWithNullSeparator() {
        Character nullChar = null;
        assertThrows(NullPointerException.class, () -> {
            Splitter.on(nullChar);
        }, "separator must not be null");
    }
}
