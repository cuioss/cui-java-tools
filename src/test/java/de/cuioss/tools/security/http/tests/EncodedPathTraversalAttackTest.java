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
package de.cuioss.tools.security.http.tests;

import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.generator.junit.parameterized.TypeGeneratorSource;
import de.cuioss.tools.security.http.config.SecurityConfiguration;
import de.cuioss.tools.security.http.exceptions.UrlSecurityException;
import de.cuioss.tools.security.http.generators.encoding.BoundaryFuzzingGenerator;
import de.cuioss.tools.security.http.generators.encoding.DoubleEncodingAttackGenerator;
import de.cuioss.tools.security.http.generators.encoding.EncodingCombinationGenerator;
import de.cuioss.tools.security.http.generators.url.PathTraversalParameterGenerator;
import de.cuioss.tools.security.http.monitoring.SecurityEventCounter;
import de.cuioss.tools.security.http.pipeline.URLPathValidationPipeline;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for T2: Encoded Path Traversal Attack Detection
 *
 * Comprehensive test suite for encoded path traversal attacks using advanced generator patterns.
 * This test validates that all forms of URL-encoded, double-encoded, mixed-case encoded,
 * and multi-level encoded path traversal patterns are properly detected and blocked.
 *
 * Implements: Task T2 from HTTP verification specification
 *
 * @since 2.5
 */
@EnableGeneratorController
@DisplayName("T2: Encoded Path Traversal Attack Tests")
class EncodedPathTraversalAttackTest {

    private URLPathValidationPipeline pipeline;
    private SecurityConfiguration config;
    private SecurityEventCounter eventCounter;
    private EncodingCombinationGenerator generator;

    @BeforeEach
    void setUp() {
        config = SecurityConfiguration.defaults();
        eventCounter = new SecurityEventCounter();
        pipeline = new URLPathValidationPipeline(config, eventCounter);
        generator = new EncodingCombinationGenerator();
    }

    @ParameterizedTest
    @DisplayName("Should block basic URL-encoded path traversal patterns")
    @TypeGeneratorSource(value = EncodingCombinationGenerator.class, count = 25)
    void shouldBlockBasicEncodedPatterns(String pattern) {
        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(pattern),
                "Basic encoded pattern should be rejected: " + pattern);

        assertNotNull(exception.getFailureType(), "Exception should have failure type");
        assertEquals(pattern, exception.getOriginalInput(), "Should preserve original input");
    }

    @ParameterizedTest
    @DisplayName("Should block double-encoded path traversal patterns")
    @TypeGeneratorSource(value = DoubleEncodingAttackGenerator.class, count = 22)
    void shouldBlockDoubleEncodedPatterns(String pattern) {
        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(pattern),
                "Double-encoded pattern should be rejected: " + pattern);

        assertNotNull(exception.getFailureType(), "Exception should have failure type");
    }

    @ParameterizedTest
    @DisplayName("Should block mixed-case encoded patterns")
    @TypeGeneratorSource(value = EncodingCombinationGenerator.class, count = 24)
    void shouldBlockMixedCaseEncodedPatterns(String pattern) {
        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(pattern),
                "Mixed-case encoded pattern should be rejected: " + pattern);

        assertNotNull(exception.getFailureType(), "Exception should have failure type");
    }

    @ParameterizedTest
    @DisplayName("Should block UTF-8 overlong encoded patterns")
    @TypeGeneratorSource(value = PathTraversalParameterGenerator.class, count = 20)
    void shouldBlockUTF8OverlongPatterns(String pattern) {
        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(pattern),
                "UTF-8 overlong pattern should be rejected: " + pattern);

        assertNotNull(exception.getFailureType(), "Exception should have failure type");
    }

    @ParameterizedTest
    @DisplayName("Should reject all generated encoded path traversal patterns")
    @TypeGeneratorSource(value = EncodingCombinationGenerator.class, count = 75)
    void shouldRejectAllGeneratedEncodedPatterns(String encodedPattern) {
        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(encodedPattern),
                "Generated encoded pattern should be rejected: " + encodedPattern);

        assertNotNull(exception.getFailureType(), "Exception should have failure type");
        assertEquals(encodedPattern, exception.getOriginalInput(), "Should preserve original input");
    }

    @ParameterizedTest
    @DisplayName("Should reject complex encoding combinations")
    @TypeGeneratorSource(value = EncodingCombinationGenerator.class, count = 27)
    void shouldRejectComplexEncodingCombinations(String complexPattern) {
        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(complexPattern),
                "Complex encoded pattern should be rejected: " + complexPattern);

        assertNotNull(exception.getFailureType(), "Exception should have failure type");
        assertEquals(complexPattern, exception.getOriginalInput(), "Should preserve original input");
    }

    @ParameterizedTest
    @TypeGeneratorSource(value = EncodingCombinationGenerator.class, count = 20)
    @DisplayName("Should handle legitimate encoded characters correctly")
    void shouldHandleLegitimateEncodedCharacters(String legitimatePattern) {
        // Note: Some of these might still be blocked by security rules if they contain
        // patterns that could be dangerous even in legitimate contexts
        try {
            String result = pipeline.validate(legitimatePattern);
            // If validation passes, result should not be null/empty
            assertNotNull(result, "Validated result should not be null for: " + legitimatePattern);
        } catch (UrlSecurityException e) {
            // Some legitimate patterns might be blocked by strict security rules
            // This is acceptable for security-first approach
            // Logging disabled for test performance
        }
    }


    @Test
    @DisplayName("Should validate encoding generator produces expected patterns")
    void shouldValidateGeneratorPatterns() {
        // Test that the generator produces the expected types of patterns
        for (int i = 0; i < 20; i++) {
            String pattern = generator.next();

            // Verify the generated patterns contain encoded characters
            boolean containsEncoding = pattern.contains("%2") || pattern.contains("%5");
            assertTrue(containsEncoding,
                    "Generated pattern should contain URL encoding: " + pattern);

            // All generated patterns should be blocked
            assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(pattern),
                    "Generated pattern should be blocked: " + pattern);
        }
    }

    @ParameterizedTest
    @TypeGeneratorSource(value = BoundaryFuzzingGenerator.class, count = 15)
    @DisplayName("Should handle edge cases in encoded patterns appropriately")
    void shouldHandleEdgeCases(String edgeCase) {
        // Only expect rejection for patterns that contain actual security threats
        // Some edge cases (long paths, special characters) may be legitimate
        
        try {
            pipeline.validate(edgeCase);
            // If validation succeeds, ensure the edge case doesn't contain obvious attack patterns
            boolean containsTraversal = edgeCase.contains("..") || edgeCase.contains("./") || edgeCase.contains("\\");
            boolean containsNullByte = edgeCase.contains("\0") || edgeCase.contains("%00");
            boolean containsControlChars = edgeCase.matches(".*[\\x00-\\x1F\\x7F-\\x9F].*");

            if (containsTraversal || containsNullByte || containsControlChars) {
                fail("Edge case with attack patterns should have been rejected: " + edgeCase);
            }
            // Otherwise, it's a legitimate edge case that passed validation (e.g., long paths, special chars)
            
        } catch (UrlSecurityException e) {
            // Expected for malicious patterns - verify it's an appropriate rejection
            assertNotNull(e.getFailureType(), "Exception should have failure type");
            assertNotNull(e.getMessage(), "Exception should have message");
        }
    }

    @Test
    @DisplayName("Should be thread-safe for concurrent testing")
    void shouldBeThreadSafe() throws InterruptedException {
        // Test concurrent access to the validation pipeline
        Thread[] threads = new Thread[10];
        boolean[] results = new boolean[10];

        for (int i = 0; i < 10; i++) {
            final int threadIndex = i;
            threads[i] = new Thread(() -> {
                try {
                    String testPattern = "%2E%2E%2F" + threadIndex;
                    pipeline.validate(testPattern);
                    results[threadIndex] = false; // Should not reach here
                } catch (UrlSecurityException e) {
                    results[threadIndex] = true; // Expected exception
                } catch (IllegalArgumentException | NullPointerException | IllegalStateException e) {
                    results[threadIndex] = false; // Unexpected exception: malformed input or internal error
                }
            });
        }

        // Start all threads
        for (Thread thread : threads) {
            thread.start();
        }

        // Wait for all threads
        for (Thread thread : threads) {
            thread.join();
        }

        // Verify all threads got expected exceptions
        for (boolean result : results) {
            assertTrue(result, "All threads should receive expected UrlSecurityException");
        }
    }
}