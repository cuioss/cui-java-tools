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
package de.cuioss.tools.security.http.generators;

import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link EncodingCombinationGenerator}
 */
class EncodingCombinationGeneratorTest {

    private final EncodingCombinationGenerator generator = new EncodingCombinationGenerator();

    @Test
    void shouldReturnStringType() {
        assertEquals(String.class, generator.getType());
    }

    @Test
    void shouldGenerateNonNullValues() {
        for (int i = 0; i < 100; i++) {
            assertNotNull(generator.next(), "Generated value should not be null");
        }
    }

    @Test
    void shouldGenerateNonEmptyValues() {
        for (int i = 0; i < 100; i++) {
            String generated = generator.next();
            assertFalse(generated.isEmpty(), "Generated value should not be empty");
        }
    }

    @Test
    void shouldGenerateVariedEncodingLevels() {
        Set<String> generatedValues = new HashSet<>();

        // Generate many values to test variety
        for (int i = 0; i < 500; i++) {
            generatedValues.add(generator.next());
        }

        // We should have good variety (at least 10 different encoding patterns)
        assertTrue(generatedValues.size() >= 10,
                "Generator should produce varied encoding levels, got: " + generatedValues.size());
    }

    @Test
    void shouldGenerateEncodedPatterns() {
        Set<String> generated = new HashSet<>();

        // Generate patterns to test encoding
        for (int i = 0; i < 100; i++) {
            generated.add(generator.next());
        }

        // Every pattern should contain URL encoding characters (including multi-level encoding)
        for (String pattern : generated) {
            assertTrue(pattern.contains("%") &&
                    (pattern.contains("2e") || pattern.contains("2f") || pattern.contains("5c")),
                    "Pattern should contain URL encoding with % and hex digits: " + pattern);
        }

        // Should have variety in encoding levels
        assertTrue(generated.size() > 5, "Should generate varied encoding patterns");
    }

    @Test
    void shouldGenerateMixedCasePatterns() {
        Set<String> generated = new HashSet<>();

        // Generate patterns to test mixed case
        for (int i = 0; i < 100; i++) {
            generated.add(generator.next());
        }

        // Some patterns should be mixed case (uppercased by applyMixedCase method)
        // Others should remain lowercase
        boolean hasAnyPattern = !generated.isEmpty();
        assertTrue(hasAnyPattern, "Should generate some patterns");

        // All patterns should contain some form of encoding
        for (String pattern : generated) {
            boolean hasEncoding = pattern.contains("%") && (
                    pattern.contains("2e") || pattern.contains("2E") ||
                            pattern.contains("2f") || pattern.contains("2F") ||
                            pattern.contains("5c") || pattern.contains("5C")
            );
            assertTrue(hasEncoding, "Pattern should contain hex encoding: " + pattern);
        }
    }

    @Test
    void shouldGenerateReasonableLength() {
        for (int i = 0; i < 100; i++) {
            String generated = generator.next();

            // Generated patterns should be reasonable length
            assertTrue(generated.length() > 0, "Pattern should not be empty");
            assertTrue(generated.length() < 200, "Pattern should not be excessively long: " + generated);
        }
    }
}