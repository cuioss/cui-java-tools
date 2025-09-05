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
 * Test for {@link PathTraversalGenerator}
 */
class PathTraversalGeneratorTest {

    private final PathTraversalGenerator generator = new PathTraversalGenerator();

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
    void shouldGenerateVariedPatterns() {
        Set<String> generatedValues = new HashSet<>();

        // Generate many values to test variety
        for (int i = 0; i < 500; i++) {
            generatedValues.add(generator.next());
        }

        // We should have good variety (at least 20 different patterns)
        assertTrue(generatedValues.size() >= 20,
                "Generator should produce varied patterns, got: " + generatedValues.size());
    }

    @Test
    void shouldGenerateKnownPathTraversalPatterns() {
        Set<String> generated = new HashSet<>();

        // Generate many patterns to catch the basic ones
        for (int i = 0; i < 1000; i++) {
            generated.add(generator.next());
        }

        // Check that we generate some expected basic patterns
        boolean hasBasicDotDot = generated.stream().anyMatch(s -> s.contains("../"));
        boolean hasEncodedDotDot = generated.stream().anyMatch(s -> s.contains("%2e%2e%2f"));
        boolean hasDoubleEncoded = generated.stream().anyMatch(s -> s.contains("%252e%252e%252f"));

        assertTrue(hasBasicDotDot, "Should generate basic ../ patterns");
        assertTrue(hasEncodedDotDot, "Should generate URL encoded patterns");
        assertTrue(hasDoubleEncoded, "Should generate double encoded patterns");
    }

    @Test
    void shouldIncludePathTraversalIndicators() {
        Set<String> generated = new HashSet<>();

        // Generate patterns to test content
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Every generated value should contain some form of traversal indicator
        for (String pattern : generated) {
            boolean hasTraversalIndicator =
                    pattern.contains("../") ||
                            pattern.contains("..\\") ||
                            pattern.contains("%2e%2e") ||
                            pattern.contains("%252e%252e") ||
                            pattern.contains("\\u002e\\u002e") ||
                            pattern.contains("\u002e\u002e") ||
                            pattern.contains("%00") ||
                            pattern.contains("....//") ||
                            pattern.contains("....\\\\") ||
                            pattern.contains("..;/") ||
                            pattern.contains("%c0%af") ||
                            pattern.contains("%c1%8s") ||
                            pattern.contains("%c1%9c");

            assertTrue(hasTraversalIndicator,
                    "Pattern should contain traversal indicators: " + pattern);
        }
    }

    @Test
    void shouldGenerateReasonableLength() {
        for (int i = 0; i < 100; i++) {
            String generated = generator.next();

            // Generated patterns should be reasonable length (not empty, not too long)
            assertTrue(generated.length() > 0, "Pattern should not be empty");
            assertTrue(generated.length() < 500, "Pattern should not be excessively long: " + generated);
        }
    }
}