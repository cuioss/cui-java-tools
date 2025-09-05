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
 * Test for {@link BoundaryFuzzingGenerator}
 */
class BoundaryFuzzingGeneratorTest {

    private final BoundaryFuzzingGenerator generator = new BoundaryFuzzingGenerator();

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
        for (int i = 0; i < 300; i++) {
            generatedValues.add(generator.next());
        }

        // We should have good variety (considering 6 different types with various patterns)
        assertTrue(generatedValues.size() >= 15,
                "Generator should produce varied boundary attack patterns, got: " + generatedValues.size());
    }

    @Test
    void shouldGenerateLongPaths() {
        Set<String> generated = new HashSet<>();

        // Generate patterns to test long paths
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for long path patterns
        boolean hasLongPaths = generated.stream().anyMatch(s -> s.length() >= 1000);

        assertTrue(hasLongPaths, "Should generate long path patterns");
    }

    @Test
    void shouldGenerateDeepNesting() {
        Set<String> generated = new HashSet<>();

        // Generate patterns to test deep nesting
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for deep nesting patterns (dir/ repeated many times)
        boolean hasDeepNesting = generated.stream().anyMatch(s -> s.contains("dir/dir/dir/dir/dir/"));

        assertTrue(hasDeepNesting, "Should generate deep nesting patterns");
    }

    @Test
    void shouldGenerateNullBytePatterns() {
        Set<String> generated = new HashSet<>();

        // Generate patterns to test null bytes
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for various null byte patterns
        boolean hasRawNull = generated.stream().anyMatch(s -> s.contains("\u0000"));
        boolean hasEncodedNull = generated.stream().anyMatch(s -> s.contains("%00"));
        boolean hasFileExtensionBypass = generated.stream().anyMatch(s -> s.contains(".jsp%00.png"));

        assertTrue(hasRawNull, "Should generate patterns with raw null bytes");
        assertTrue(hasEncodedNull, "Should generate patterns with encoded null bytes");
        assertTrue(hasFileExtensionBypass, "Should generate extension bypass patterns");
    }

    @Test
    void shouldGenerateControlCharacters() {
        Set<String> generated = new HashSet<>();

        // Generate patterns to test control characters
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for control character patterns
        boolean hasCRLF = generated.stream().anyMatch(s -> s.contains("\r\n"));
        boolean hasTab = generated.stream().anyMatch(s -> s.contains("\t"));
        boolean hasBackspace = generated.stream().anyMatch(s -> s.contains("\b"));
        boolean hasUnitSeparator = generated.stream().anyMatch(s -> s.contains("\u001F"));

        assertTrue(hasCRLF, "Should generate CRLF injection patterns");
        assertTrue(hasTab, "Should generate tab character patterns");
        assertTrue(hasBackspace, "Should generate backspace patterns");
        assertTrue(hasUnitSeparator, "Should generate unit separator patterns");
    }

    @Test
    void shouldGenerateMixedBoundaryAttacks() {
        Set<String> generated = new HashSet<>();

        // Generate patterns to test mixed boundary attacks
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for mixed boundary attack patterns
        boolean hasExcessiveTraversal = generated.stream().anyMatch(s -> s.contains("../") && s.contains("etc/passwd"));
        boolean hasNearMaxLength = generated.stream().anyMatch(s -> s.startsWith("/a") && s.length() > 1000);
        boolean hasNullPlusTraversal = generated.stream().anyMatch(s -> s.contains("/%00") && s.contains("../"));

        assertTrue(hasExcessiveTraversal, "Should generate excessive traversal patterns");
        assertTrue(hasNearMaxLength, "Should generate near max length patterns");
        assertTrue(hasNullPlusTraversal, "Should generate null byte plus traversal patterns");
    }

    @Test
    void shouldGenerateSpecialCharacters() {
        Set<String> generated = new HashSet<>();

        // Generate patterns to test special characters
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for special character patterns
        boolean hasPipe = generated.stream().anyMatch(s -> s.contains("|command"));
        boolean hasSemicolon = generated.stream().anyMatch(s -> s.contains(";command"));
        boolean hasBackticks = generated.stream().anyMatch(s -> s.contains("`command`"));
        boolean hasVariableExpansion = generated.stream().anyMatch(s -> s.contains("$variable"));
        boolean hasRedirection = generated.stream().anyMatch(s -> s.contains(">output"));

        assertTrue(hasPipe, "Should generate pipe character patterns");
        assertTrue(hasSemicolon, "Should generate semicolon patterns");
        assertTrue(hasBackticks, "Should generate backtick patterns");
        assertTrue(hasVariableExpansion, "Should generate variable expansion patterns");
        assertTrue(hasRedirection, "Should generate redirection patterns");
    }

    @Test
    void shouldGenerateReasonableVariety() {
        Set<String> generated = new HashSet<>();

        // Generate a large set to test overall variety
        for (int i = 0; i < 500; i++) {
            generated.add(generator.next());
        }

        // Should have patterns from different categories
        boolean hasLong = generated.stream().anyMatch(s -> s.length() > 500);
        boolean hasShort = generated.stream().anyMatch(s -> s.length() < 50);
        boolean hasSpecialChars = generated.stream().anyMatch(s -> s.matches(".*[|;`$>].*"));
        boolean hasControlChars = generated.stream().anyMatch(s -> s.matches(".*[\r\n\t\b].*"));

        assertTrue(hasLong, "Should generate long patterns");
        assertTrue(hasShort, "Should generate short patterns");
        assertTrue(hasSpecialChars, "Should generate patterns with special characters");
        assertTrue(hasControlChars, "Should generate patterns with control characters");
    }

    @Test
    void shouldGeneratePathTraversalCombinations() {
        Set<String> generated = new HashSet<>();

        // Generate patterns to test path traversal combinations
        for (int i = 0; i < 200; i++) {
            generated.add(generator.next());
        }

        // Check for path traversal combinations
        boolean hasTraversalWithNull = generated.stream().anyMatch(s -> s.contains("../") && s.contains("\u0000"));
        boolean hasTraversalWithSpecial = generated.stream().anyMatch(s -> s.contains("../") && s.contains("passwd"));

        assertTrue(hasTraversalWithNull, "Should generate path traversal with null byte combinations");
        assertTrue(hasTraversalWithSpecial, "Should generate path traversal with special file combinations");
    }
}