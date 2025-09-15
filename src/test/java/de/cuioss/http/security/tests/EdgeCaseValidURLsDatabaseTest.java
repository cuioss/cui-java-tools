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
package de.cuioss.http.security.tests;

import de.cuioss.http.security.config.SecurityConfiguration;
import de.cuioss.http.security.database.EdgeCaseValidURLsDatabase;
import de.cuioss.http.security.database.LegitimateTestCase;
import de.cuioss.http.security.monitoring.SecurityEventCounter;
import de.cuioss.http.security.pipeline.URLPathValidationPipeline;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for Edge Case Valid URLs Database (T33).
 *
 * <p><strong>FALSE POSITIVE PREVENTION:</strong> This test class validates that edge case
 * URL patterns are properly accepted by the security validation pipeline despite being
 * unusual. Each test case represents a technically valid URL that might appear suspicious
 * but is legitimate according to RFC specifications.</p>
 *
 * <p>This test ensures that unusual but valid URL constructs like minimal paths,
 * repetitive patterns, extreme lengths, and RFC edge cases are correctly accepted
 * without triggering false positives.</p>
 *
 * <h3>Test Coverage</h3>
 * <ul>
 *   <li><strong>Minimal Paths</strong>: Single character, root only</li>
 *   <li><strong>Repetitive</strong>: Repeated segments, multiple dots/hyphens</li>
 *   <li><strong>Length Extremes</strong>: Very long segments, deep nesting</li>
 *   <li><strong>RFC Edge Cases</strong>: Empty segments, matrix parameters</li>
 *   <li><strong>Numeric Edge Cases</strong>: All numeric, leading zeros, negatives</li>
 * </ul>
 *
 * @author Claude Code Generator
 * @since 2.5
 */
@DisplayName("Edge Case Valid URLs Database Tests (T33)")
class EdgeCaseValidURLsDatabaseTest {

    private URLPathValidationPipeline pipeline;
    private SecurityEventCounter eventCounter;

    @BeforeEach
    void setUp() {
        // Use a permissive configuration for edge cases
        SecurityConfiguration config = SecurityConfiguration.builder()
                .allowHighBitCharacters(true)
                .maxPathLength(1000)  // Allow longer paths for edge cases
                .build();
        eventCounter = new SecurityEventCounter();
        pipeline = new URLPathValidationPipeline(config, eventCounter);
    }

    /**
     * Parameterized test that validates all edge case URL patterns.
     * These unusual patterns should still be accepted as valid.
     *
     * @param testCase LegitimateTestCase containing pattern and documentation
     */
    @ParameterizedTest
    @ArgumentsSource(EdgeCaseValidURLsDatabase.ArgumentsProvider.class)
    @DisplayName("Edge case valid URLs should be accepted without false positives")
    void shouldAcceptEdgeCaseValidURLs(LegitimateTestCase testCase) {
        // Given: An edge case URL pattern that is technically valid
        long initialEventCount = eventCounter.getTotalCount();

        // When/Then: Validating the edge case should NOT throw an exception
        assertDoesNotThrow(
                () -> pipeline.validate(testCase.legitimatePattern()),
                "Edge case URL should be accepted: %s\nDescription: %s\nRationale: %s".formatted(
                        testCase.legitimatePattern(),
                        testCase.description(),
                        testCase.acceptanceRationale())
        );

        // And: No security events should be recorded for valid edge cases
        assertEquals(initialEventCount, eventCounter.getTotalCount(),
                "No security events should be recorded for valid edge case: %s".formatted(
                        testCase.getCompactSummary()));
    }

    /**
     * Test that edge cases are handled consistently.
     */
    @ParameterizedTest
    @ArgumentsSource(EdgeCaseValidURLsDatabase.ArgumentsProvider.class)
    @DisplayName("Edge case URLs should be consistently accepted")
    void shouldConsistentlyAcceptEdgeCases(LegitimateTestCase testCase) {
        // Validate multiple times to ensure edge case handling is stable
        for (int i = 0; i < 3; i++) {
            assertDoesNotThrow(
                    () -> pipeline.validate(testCase.legitimatePattern()),
                    "Edge case should be consistently accepted on validation #%d: %s".formatted(
                            i + 1, testCase.legitimatePattern())
            );
        }
    }

    /**
     * Verify that edge cases don't cause performance issues.
     */
    @ParameterizedTest
    @ArgumentsSource(EdgeCaseValidURLsDatabase.ArgumentsProvider.class)
    @DisplayName("Edge case URLs should be processed efficiently")
    void shouldProcessEdgeCasesEfficiently(LegitimateTestCase testCase) {
        long startTime = System.nanoTime();

        assertDoesNotThrow(() -> {
            pipeline.validate(testCase.legitimatePattern());
        }, "Edge case processing should complete: %s".formatted(
                testCase.legitimatePattern()));

        long elapsedMs = (System.nanoTime() - startTime) / 1_000_000;

        // Edge cases should still be processed quickly (under 100ms)
        assertTrue(elapsedMs < 100,
                "Edge case should be processed quickly (was %dms): %s".formatted(
                        elapsedMs, testCase.legitimatePattern()));
    }

    /**
     * Verify that the pipeline handles edge cases without internal errors.
     */
    @ParameterizedTest
    @ArgumentsSource(EdgeCaseValidURLsDatabase.ArgumentsProvider.class)
    @DisplayName("Edge case URLs should not cause internal errors")
    void shouldHandleEdgeCasesWithoutInternalErrors(LegitimateTestCase testCase) {
        // The validation should complete without any exceptions
        assertDoesNotThrow(() -> {
            pipeline.validate(testCase.legitimatePattern());
        }, "Edge case should not cause internal errors: %s".formatted(
                testCase.legitimatePattern()));

        // Event counter should remain at zero (no warnings/errors)
        assertEquals(0, eventCounter.getTotalCount(),
                "No internal errors should be logged for edge case: %s".formatted(
                        testCase.legitimatePattern()));
    }
}