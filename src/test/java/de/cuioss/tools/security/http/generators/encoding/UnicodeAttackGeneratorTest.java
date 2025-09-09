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
package de.cuioss.tools.security.http.generators.encoding;

import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link UnicodeAttackGenerator}
 */
class UnicodeAttackGeneratorTest {

    private final UnicodeAttackGenerator generator = new UnicodeAttackGenerator();

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
    void shouldGenerateVariedPatterns() {
        Set<String> generatedValues = new HashSet<>();

        // Generate many values to test variety
        for (int i = 0; i < 200; i++) {
            generatedValues.add(generator.next());
        }

        // We should have good variety (at least 8 different patterns)
        assertTrue(generatedValues.size() >= 8,
                "Generator should produce varied Unicode attack patterns, got: " + generatedValues.size());
    }

    @Test
    void shouldGenerateUnicodeCharacters() {
        Set<String> generated = new HashSet<>();

        // Generate patterns to test Unicode content
        for (int i = 0; i < 100; i++) {
            generated.add(generator.next());
        }

        // Check that we generate patterns with specific Unicode characters
        boolean hasUnicodeDots = generated.stream().anyMatch(s -> s.contains("\u002e\u002e\u002f"));
        boolean hasLookalikeChars = generated.stream().anyMatch(s -> s.contains("\u2024\u2024\u2215"));
        boolean hasRightToLeft = generated.stream().anyMatch(s -> s.contains("\u202e"));
        boolean hasZeroWidthSpace = generated.stream().anyMatch(s -> s.contains("\u200b"));

        assertTrue(hasUnicodeDots, "Should generate Unicode dots and slash patterns");
        assertTrue(hasLookalikeChars, "Should generate lookalike character patterns");
        assertTrue(hasRightToLeft, "Should generate right-to-left override patterns");
        assertTrue(hasZeroWidthSpace, "Should generate zero-width space patterns");
    }

    @Test
    void shouldGeneratePathTraversalCombinations() {
        Set<String> generated = new HashSet<>();

        // Generate many patterns to catch combinations
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check that some patterns are combined with path traversal
        boolean hasCombinedPatterns = generated.stream().anyMatch(s -> s.contains("../etc/passwd"));

        assertTrue(hasCombinedPatterns, "Should generate some patterns combined with path traversal");
    }

    @Test
    void shouldGenerateStandaloneUnicodePatterns() {
        Set<String> generated = new HashSet<>();

        // Generate patterns
        for (int i = 0; i < 100; i++) {
            generated.add(generator.next());
        }

        // Check that some patterns are standalone (not combined)
        boolean hasStandalonePatterns = generated.stream().anyMatch(s -> !s.contains("../etc/passwd"));

        assertTrue(hasStandalonePatterns, "Should generate some standalone Unicode patterns");
    }

    @Test
    void shouldGenerateReasonableLength() {
        for (int i = 0; i < 100; i++) {
            String generated = generator.next();

            // Generated patterns should be reasonable length
            assertTrue(generated.length() >= 1, "Pattern should not be empty");
            assertTrue(generated.length() < 100, "Pattern should not be excessively long: " + generated);
        }
    }

    @Test
    void shouldContainSpecialUnicodeCharacters() {
        Set<String> generated = new HashSet<>();

        // Generate patterns to test special characters
        for (int i = 0; i < 100; i++) {
            generated.add(generator.next());
        }

        // Check for specific problematic Unicode characters
        boolean hasNullChar = generated.stream().anyMatch(s -> s.contains("\u0000"));
        boolean hasZeroWidthNoBreak = generated.stream().anyMatch(s -> s.contains("\uFEFF"));

        assertTrue(hasNullChar, "Should generate patterns with null character");
        assertTrue(hasZeroWidthNoBreak, "Should generate patterns with zero-width no-break space");
    }
}