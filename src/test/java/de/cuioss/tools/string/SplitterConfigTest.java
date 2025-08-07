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

import de.cuioss.test.generator.Generators;
import de.cuioss.tools.support.ObjectMethodsAsserts;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("SplitterConfig")
class SplitterConfigTest {

    @Nested
    @DisplayName("Builder Pattern")
    class BuilderTests {

        @Test
        @DisplayName("Should build with default values")
        void shouldBuildWithDefaults() {
            var separator = Generators.nonEmptyStrings().next();
            var config = SplitterConfig.builder()
                    .separator(separator)
                    .build();

            assertEquals(separator, config.getSeparator());
            assertFalse(config.isOmitEmptyStrings());
            assertFalse(config.isTrimResults());
            assertEquals(0, config.getMaxItems());
            assertFalse(config.isDoNotModifySeparatorString());
            assertNull(config.getPattern());
        }

        @Test
        @DisplayName("Should build with custom values")
        void shouldBuildWithCustomValues() {
            var separator = Generators.nonEmptyStrings().next();
            var maxItems = Generators.integers(1, 100).next();
            var pattern = Pattern.compile("[,;]");

            var config = SplitterConfig.builder()
                    .separator(separator)
                    .omitEmptyStrings(true)
                    .trimResults(true)
                    .maxItems(maxItems)
                    .doNotModifySeparatorString(true)
                    .pattern(pattern)
                    .build();

            assertEquals(separator, config.getSeparator());
            assertTrue(config.isOmitEmptyStrings());
            assertTrue(config.isTrimResults());
            assertEquals(maxItems, config.getMaxItems());
            assertTrue(config.isDoNotModifySeparatorString());
            assertEquals(pattern, config.getPattern());
        }

        @Test
        @DisplayName("Should support fluent API")
        void shouldSupportFluentApi() {
            var separator = Generators.nonEmptyStrings().next();

            var config = SplitterConfig.builder()
                    .separator(separator)
                    .omitEmptyStrings(true)
                    .trimResults(false)
                    .omitEmptyStrings(false)  // Should override previous setting
                    .build();

            assertFalse(config.isOmitEmptyStrings()); // Verify last setting takes precedence
        }
    }

    @Nested
    @DisplayName("Configuration Properties")
    class PropertyTests {

        @Test
        @DisplayName("Should handle all boolean combinations")
        void shouldHandleAllBooleanCombinations() {
            var separator = Generators.nonEmptyStrings().next();

            // Test all combinations of boolean flags
            boolean[] values = {false, true};

            for (boolean omitEmpty : values) {
                for (boolean trimResults : values) {
                    for (boolean doNotModify : values) {
                        var config = SplitterConfig.builder()
                                .separator(separator)
                                .omitEmptyStrings(omitEmpty)
                                .trimResults(trimResults)
                                .doNotModifySeparatorString(doNotModify)
                                .build();

                        assertEquals(omitEmpty, config.isOmitEmptyStrings());
                        assertEquals(trimResults, config.isTrimResults());
                        assertEquals(doNotModify, config.isDoNotModifySeparatorString());
                    }
                }
            }
        }

        @Test
        @DisplayName("Should handle maxItems variations")
        void shouldHandleMaxItemsVariations() {
            var separator = Generators.nonEmptyStrings().next();
            int[] maxItemsValues = {-1, 0, 1, 5, 100, Integer.MAX_VALUE};

            for (int maxItems : maxItemsValues) {
                var config = SplitterConfig.builder()
                        .separator(separator)
                        .maxItems(maxItems)
                        .build();

                assertEquals(maxItems, config.getMaxItems());
            }
        }

        @Test
        @DisplayName("Should handle null pattern")
        void shouldHandleNullPattern() {
            var config = SplitterConfig.builder()
                    .separator(Generators.nonEmptyStrings().next())
                    .pattern(null)
                    .build();

            assertNull(config.getPattern());
        }

        @Test
        @DisplayName("Should handle empty separator")
        void shouldHandleEmptySeparator() {
            var config = SplitterConfig.builder()
                    .separator("")
                    .build();

            assertEquals("", config.getSeparator());
        }
    }

    @Nested
    @DisplayName("Pattern Handling")
    class PatternTests {

        @Test
        @DisplayName("Should handle common regex patterns")
        void shouldHandleCommonPatterns() {
            String[] regexPatterns = {
                    "[,;]",           // Character class
                    "\\s+",           // Whitespace
                    "\\d+",           // Digits
                    "[a-zA-Z]+",      // Letters
                    "\\|",            // Escaped pipe
                    "\\s*,\\s*"       // Comma with optional whitespace
            };

            for (String regex : regexPatterns) {
                var pattern = Pattern.compile(regex);
                var config = SplitterConfig.builder()
                        .separator(Generators.nonEmptyStrings().next())
                        .pattern(pattern)
                        .build();

                assertEquals(pattern, config.getPattern());
            }
        }

        @Test
        @DisplayName("Should handle pattern flags")
        void shouldHandlePatternFlags() {
            var pattern = Pattern.compile("[a-z]+", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
            var config = SplitterConfig.builder()
                    .separator(Generators.nonEmptyStrings().next())
                    .pattern(pattern)
                    .build();

            assertEquals(pattern, config.getPattern());
            assertEquals(Pattern.CASE_INSENSITIVE | Pattern.MULTILINE, config.getPattern().flags());
        }
    }

    @Nested
    @DisplayName("Copy Method")
    class CopyTests {

        @Test
        @DisplayName("Should create identical copy")
        void shouldCreateIdenticalCopy() {
            var original = SplitterConfig.builder()
                    .separator(Generators.nonEmptyStrings().next())
                    .omitEmptyStrings(true)
                    .trimResults(true)
                    .maxItems(10)
                    .doNotModifySeparatorString(true)
                    .pattern(Pattern.compile("[,;]"))
                    .build();

            var copy = original.copy().build();

            assertEquals(original.getSeparator(), copy.getSeparator());
            assertEquals(original.isOmitEmptyStrings(), copy.isOmitEmptyStrings());
            assertEquals(original.isTrimResults(), copy.isTrimResults());
            assertEquals(original.getMaxItems(), copy.getMaxItems());
            assertEquals(original.isDoNotModifySeparatorString(), copy.isDoNotModifySeparatorString());
            assertEquals(original.getPattern(), copy.getPattern());
        }

        @Test
        @DisplayName("Should allow modification of copy")
        void shouldAllowModificationOfCopy() {
            var original = SplitterConfig.builder()
                    .separator(",")
                    .omitEmptyStrings(false)
                    .build();

            var modified = original.copy()
                    .omitEmptyStrings(true)
                    .trimResults(true)
                    .build();

            // Original should be unchanged
            assertFalse(original.isOmitEmptyStrings());
            assertFalse(original.isTrimResults());

            // Modified copy should have new values
            assertTrue(modified.isOmitEmptyStrings());
            assertTrue(modified.isTrimResults());
            assertEquals(",", modified.getSeparator()); // Copied value
        }
    }

    @Nested
    @DisplayName("Edge Cases")
    class EdgeCaseTests {

        @Test
        @DisplayName("Should handle special characters in separator")
        void shouldHandleSpecialCharacters() {
            String[] specialSeparators = {"\n", "\t", "\r\n", "\\", "\"", "'", "|", ",", ";", " | "};

            for (String separator : specialSeparators) {
                var config = SplitterConfig.builder()
                        .separator(separator)
                        .build();

                assertEquals(separator, config.getSeparator());
            }
        }

        @Test
        @DisplayName("Should handle unicode characters")
        void shouldHandleUnicodeCharacters() {
            String[] unicodeSeparators = {"→", "•", "★", "中文", "🔗"};

            for (String separator : unicodeSeparators) {
                var config = SplitterConfig.builder()
                        .separator(separator)
                        .build();

                assertEquals(separator, config.getSeparator());
            }
        }
    }

    @Test
    @DisplayName("Should implement object contracts correctly")
    void shouldImplementObjectContracts() {
        var config = SplitterConfig.builder()
                .separator(Generators.nonEmptyStrings().next())
                .omitEmptyStrings(Generators.booleans().next())
                .trimResults(Generators.booleans().next())
                .maxItems(Generators.integers(1, 100).next())
                .doNotModifySeparatorString(Generators.booleans().next())
                .pattern(Pattern.compile("[,;]"))
                .build();

        // Test equals and hashCode contracts (skip serialization as class doesn't implement Serializable)
        ObjectMethodsAsserts.assertEqualsAndHashCode(config);
        ObjectMethodsAsserts.assertToString(config);
    }
}