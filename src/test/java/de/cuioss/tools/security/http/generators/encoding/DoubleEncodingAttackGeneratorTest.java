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
 * Test for {@link DoubleEncodingAttackGenerator}
 */
class DoubleEncodingAttackGeneratorTest {

    private final DoubleEncodingAttackGenerator generator = new DoubleEncodingAttackGenerator();

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
    void shouldGenerateDoubleEncodingPatterns() {
        Set<String> generated = new HashSet<>();

        // Generate patterns to test double encoding
        for (int i = 0; i < 100; i++) {
            generated.add(generator.next());
        }

        // Every pattern should contain double encoding indicators
        for (String pattern : generated) {
            boolean hasDoubleEncoding = pattern.contains("%252") ||  // Standard double encoding
                    pattern.contains("%%3") ||                           // CVE-style double encoding  
                    pattern.contains("%25252") ||                        // Triple encoding
                    pattern.contains("%255");                            // Double encoding of backslash
            assertTrue(hasDoubleEncoding,
                    "Pattern should contain double encoding: " + pattern);
        }

        // Should have variety in patterns
        assertTrue(generated.size() >= 10, "Should generate varied double encoding patterns");
    }

    @Test
    void shouldGeneratePathTraversalPatterns() {
        Set<String> generated = new HashSet<>();

        // Generate patterns to test path traversal elements
        for (int i = 0; i < 100; i++) {
            generated.add(generator.next());
        }

        // Should contain path traversal patterns (either in encoded form)
        boolean hasTraversalElements = generated.stream()
                .anyMatch(s -> s.contains("252e") || s.contains("252f") ||
                        s.contains("../") || s.contains("etc"));

        assertTrue(hasTraversalElements, "Should generate patterns with traversal elements");
    }

    @Test
    void shouldGenerateCVEPatterns() {
        Set<String> generated = new HashSet<>();

        // Generate patterns to test CVE-specific attacks
        for (int i = 0; i < 100; i++) {
            generated.add(generator.next());
        }

        // Should contain CVE-2021-42013 patterns
        boolean hasCVEPatterns = generated.stream()
                .anyMatch(s -> s.contains("%%32%65") || s.contains("%%32%66"));

        assertTrue(hasCVEPatterns, "Should generate CVE-related attack patterns");
    }

    @Test
    void shouldGenerateReasonableLength() {
        for (int i = 0; i < 100; i++) {
            String generated = generator.next();

            // Generated patterns should be reasonable length
            assertTrue(generated.length() > 0, "Pattern should not be empty");
            assertTrue(generated.length() < 500, "Pattern should not be excessively long: " + generated);
        }
    }
}