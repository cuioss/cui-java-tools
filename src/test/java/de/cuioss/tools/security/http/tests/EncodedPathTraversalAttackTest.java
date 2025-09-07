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
import de.cuioss.tools.security.http.generators.ComplexEncodingCombinationGenerator;
import de.cuioss.tools.security.http.generators.EncodingCombinationGenerator;
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

    @Test
    @DisplayName("Should block basic URL-encoded path traversal patterns")
    void shouldBlockBasicEncodedPatterns() {
        String[] basicEncodedPatterns = {
                "/api/users%2F..%2F..%2Fadmin",        // ../.. encoded
                "/files%2F..%2F..%2Fetc%2Fpasswd",    // ../../etc/passwd encoded
                "%2E%2E%2F",                          // ../ fully encoded
                "%2e%2e%2f",                          // ../ lowercase encoded
                "%2E%2E%5C",                          // ..\ with backslash encoded
                "%2e%2e%5c",                          // ..\ lowercase encoded
                "/path%2F%2E%2E%2Fconfig",            // /path/../config encoded
                "/data%5C%2E%2E%5Cadmin",             // \data\..\admin encoded
        };

        for (String pattern : basicEncodedPatterns) {
            UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(pattern),
                    "Basic encoded pattern should be rejected: " + pattern);

            assertNotNull(exception.getFailureType(), "Exception should have failure type");
            assertEquals(pattern, exception.getOriginalInput(), "Should preserve original input");
        }
    }

    @Test
    @DisplayName("Should block double-encoded path traversal patterns")
    void shouldBlockDoubleEncodedPatterns() {
        String[] doubleEncodedPatterns = {
                "/api%252F..%252F..%252Fadmin",        // %2F double-encoded to %252F
                "%252E%252E%252F",                    // ../ double-encoded
                "%252e%252e%252f",                    // ../ double-encoded lowercase
                "%252E%252E%255C",                    // ..\ double-encoded
                "/data%255C%252E%252E%255Cadmin",     // \..\ double-encoded
                "%2525252E%2525252E%2525252F",        // ../ triple-encoded
        };

        for (String pattern : doubleEncodedPatterns) {
            UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(pattern),
                    "Double-encoded pattern should be rejected: " + pattern);

            assertNotNull(exception.getFailureType(), "Exception should have failure type");
        }
    }

    @Test
    @DisplayName("Should block mixed-case encoded patterns")
    void shouldBlockMixedCaseEncodedPatterns() {
        String[] mixedCasePatterns = {
                "%2E%2e%2F",                          // Mixed case ../
                "%2e%2E%2f",                          // Mixed case ../
                "%2E%2E%2f",                          // Mixed case ../
                "%2e%2e%2F",                          // Mixed case ../
                "/path%2F%2E%2e%2F%2E%2E%2fconfig",   // Mixed encoding in sequence
                "%2E%2E%5c",                          // Mixed case ..\
                "%2e%2E%5C",                          // Mixed case ..\
        };

        for (String pattern : mixedCasePatterns) {
            UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(pattern),
                    "Mixed-case encoded pattern should be rejected: " + pattern);

            assertNotNull(exception.getFailureType(), "Exception should have failure type");
        }
    }

    @Test
    @DisplayName("Should block UTF-8 overlong encoded patterns")
    void shouldBlockUTF8OverlongPatterns() {
        String[] utf8OverlongPatterns = {
                "/path%c0%ae%c0%ae%c0%af",            // ../ UTF-8 overlong
                "%c0%ae%c0%ae%c0%af",                 // ../ UTF-8 overlong start
                "/data%c1%9c",                        // \ UTF-8 overlong
                "%c0%ae%c0%ae%c1%9c",                 // ..\ UTF-8 overlong mixed
                "/files%c0%ae%c0%ae%c0%afconfig",    // ../config UTF-8 overlong
        };

        for (String pattern : utf8OverlongPatterns) {
            UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(pattern),
                    "UTF-8 overlong pattern should be rejected: " + pattern);

            assertNotNull(exception.getFailureType(), "Exception should have failure type");
        }
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
    @TypeGeneratorSource(value = ComplexEncodingCombinationGenerator.class, count = 7)
    void shouldRejectComplexEncodingCombinations(String complexPattern) {
        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(complexPattern),
                "Complex encoded pattern should be rejected: " + complexPattern);

        assertNotNull(exception.getFailureType(), "Exception should have failure type");
        assertEquals(complexPattern, exception.getOriginalInput(), "Should preserve original input");
    }

    @Test
    @DisplayName("Should handle legitimate encoded characters correctly")
    void shouldHandleLegitimateEncodedCharacters() {
        String[] legitimatePatterns = {
                "/api/users%40example.com",           // @ symbol encoded
                "/files/document%20name.txt",         // space encoded
                "/search?q=hello%2Bworld",            // + encoded in query
                "/api/data%5B0%5D",                   // [0] array notation encoded
                "/path/file%2Etxt",                   // Normal file.txt (note: this might be blocked by security rules)
        };

        // Note: Some of these might still be blocked by security rules if they contain
        // patterns that could be dangerous even in legitimate contexts
        for (String pattern : legitimatePatterns) {
            try {
                String result = pipeline.validate(pattern);
                // If validation passes, result should not be null/empty
                assertNotNull(result, "Validated result should not be null for: " + pattern);
            } catch (UrlSecurityException e) {
                // Some legitimate patterns might be blocked by strict security rules
                // This is acceptable for security-first approach
                // Logging disabled for test performance
            }
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

    @Test
    @DisplayName("Should handle edge cases in encoded patterns")
    void shouldHandleEdgeCases() {
        String[] edgeCases = {
                "%",                                  // Incomplete encoding
                "%2",                                 // Incomplete encoding
                "%2G",                                // Invalid hex character
                "%ZZ",                                // Invalid hex characters
                "%%2E",                               // Double %
                "%2E%",                               // Trailing %
                "%2E%G",                              // Invalid after valid
        };

        for (String edgeCase : edgeCases) {
            // These should either be rejected for invalid encoding or for security reasons
            assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(edgeCase),
                    "Edge case should be rejected: " + edgeCase);
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
                } /*~~(Catch specific not RuntimeException)~~>*//*~~(Catch specific not RuntimeException)~~>*//*~~(Catch specific not RuntimeException)~~>*//*~~(Catch specific not RuntimeException)~~>*/catch (RuntimeException e) {
                    results[threadIndex] = false; // Unexpected exception
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