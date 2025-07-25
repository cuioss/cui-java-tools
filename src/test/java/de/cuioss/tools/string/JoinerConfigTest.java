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

import de.cuioss.tools.support.Generators;
import de.cuioss.tools.support.ObjectMethodsAsserts;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("JoinerConfig")
class JoinerConfigTest {

    @Nested
    @DisplayName("Builder Pattern")
    class BuilderTests {

        @Test
        @DisplayName("Should build with default values")
        void shouldBuildWithDefaults() {
            var separator = Generators.randomString();
            var config = JoinerConfig.builder()
                    .separator(separator)
                    .build();

            assertEquals(separator, config.getSeparator());
            assertFalse(config.isSkipNulls());
            assertFalse(config.isSkipEmpty());
            assertFalse(config.isSkipBlank());
            assertEquals("null", config.getUseForNull());
        }

        @Test
        @DisplayName("Should build with custom values")
        void shouldBuildWithCustomValues() {
            var separator = Generators.randomString();
            var useForNull = Generators.randomString();

            var config = JoinerConfig.builder()
                    .separator(separator)
                    .skipNulls(true)
                    .skipEmpty(true)
                    .skipBlank(true)
                    .useForNull(useForNull)
                    .build();

            assertEquals(separator, config.getSeparator());
            assertTrue(config.isSkipNulls());
            assertTrue(config.isSkipEmpty());
            assertTrue(config.isSkipBlank());
            assertEquals(useForNull, config.getUseForNull());
        }

        @Test
        @DisplayName("Should support fluent API")
        void shouldSupportFluentApi() {
            var separator = Generators.randomString();
            var useForNull = Generators.randomString();

            var config = JoinerConfig.builder()
                    .separator(separator)
                    .skipNulls(true)
                    .skipEmpty(false)
                    .skipBlank(true)
                    .useForNull(useForNull)
                    .skipNulls(false)  // Should override previous setting
                    .build();

            assertFalse(config.isSkipNulls()); // Verify last setting takes precedence
        }
    }

    @Nested
    @DisplayName("Configuration Properties")
    class PropertyTests {

        @Test
        @DisplayName("Should handle all boolean combinations")
        void shouldHandleAllBooleanCombinations() {
            var separator = Generators.randomString();

            // Test all 8 combinations of the three boolean flags
            boolean[] values = {false, true};

            for (boolean skipNulls : values) {
                for (boolean skipEmpty : values) {
                    for (boolean skipBlank : values) {
                        var config = JoinerConfig.builder()
                                .separator(separator)
                                .skipNulls(skipNulls)
                                .skipEmpty(skipEmpty)
                                .skipBlank(skipBlank)
                                .build();

                        assertEquals(skipNulls, config.isSkipNulls());
                        assertEquals(skipEmpty, config.isSkipEmpty());
                        assertEquals(skipBlank, config.isSkipBlank());
                    }
                }
            }
        }

        @Test
        @DisplayName("Should handle null useForNull value")
        void shouldHandleNullUseForNull() {
            var config = JoinerConfig.builder()
                    .separator(Generators.randomString())
                    .useForNull(null)
                    .build();

            assertNull(config.getUseForNull());
        }

        @Test
        @DisplayName("Should handle empty separator")
        void shouldHandleEmptySeparator() {
            var config = JoinerConfig.builder()
                    .separator("")
                    .build();

            assertEquals("", config.getSeparator());
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
                var config = JoinerConfig.builder()
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
                var config = JoinerConfig.builder()
                        .separator(separator)
                        .build();

                assertEquals(separator, config.getSeparator());
            }
        }
    }

    @Test
    @DisplayName("Should implement object contracts correctly")
    void shouldImplementObjectContracts() {
        var config = JoinerConfig.builder()
                .separator(Generators.randomString())
                .skipNulls(Generators.randomBoolean())
                .skipEmpty(Generators.randomBoolean())
                .skipBlank(Generators.randomBoolean())
                .useForNull(Generators.randomString())
                .build();

        // Test equals and hashCode contracts (skip serialization as class doesn't implement Serializable)
        ObjectMethodsAsserts.assertEqualsAndHashCode(config);
        ObjectMethodsAsserts.assertToString(config);
    }
}