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
import de.cuioss.http.security.database.LegitimatePathPatternsDatabase;
import de.cuioss.http.security.database.LegitimateTestCase;
import de.cuioss.http.security.monitoring.SecurityEventCounter;
import de.cuioss.http.security.pipeline.URLPathValidationPipeline;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for Legitimate Path Patterns Database (T31).
 *
 * <p><strong>FALSE POSITIVE PREVENTION:</strong> This test class validates that all
 * legitimate path patterns are properly accepted by the security validation pipeline
 * without triggering false positives. Each test case represents a valid business use
 * case that must not be rejected.</p>
 *
 * <p>This test ensures that common web application patterns like RESTful APIs,
 * static resources, framework paths, and deep hierarchies are correctly accepted
 * by the validation system.</p>
 *
 * <h3>Test Coverage</h3>
 * <ul>
 *   <li><strong>RESTful APIs</strong>: Version paths, resource IDs, nested resources</li>
 *   <li><strong>Static Resources</strong>: Versioned assets, hashed bundles</li>
 *   <li><strong>Framework Patterns</strong>: Spring, Angular, WordPress paths</li>
 *   <li><strong>Date/Time Paths</strong>: Blog posts, timestamps</li>
 *   <li><strong>International</strong>: Properly encoded UTF-8 characters</li>
 * </ul>
 *
 * @author Claude Code Generator
 * @since 2.5
 */
@DisplayName("Legitimate Path Patterns Database Tests (T31)")
class LegitimatePathPatternsDatabaseTest {

    private URLPathValidationPipeline pipeline;
    private SecurityEventCounter eventCounter;

    @BeforeEach
    void setUp() {
        // Use a configuration that allows legitimate patterns
        SecurityConfiguration config = SecurityConfiguration.builder()
                .allowHighBitCharacters(true)  // Allow UTF-8 encoded international characters
                .maxPathLength(500)  // Allow reasonably long paths
                .build();
        eventCounter = new SecurityEventCounter();
        pipeline = new URLPathValidationPipeline(config, eventCounter);
    }

    /**
     * Parameterized test that validates all legitimate path patterns from the database.
     * These patterns should NOT throw exceptions and should be accepted as valid.
     *
     * @param testCase LegitimateTestCase containing pattern and documentation
     */
    @ParameterizedTest
    @ArgumentsSource(LegitimatePathPatternsDatabase.ArgumentsProvider.class)
    @DisplayName("Legitimate path patterns should be accepted without false positives")
    void shouldAcceptLegitimatePathPatterns(LegitimateTestCase testCase) {
        // Given: A legitimate path pattern that represents a valid business use case
        long initialEventCount = eventCounter.getTotalCount();

        // When/Then: Validating the legitimate pattern should NOT throw an exception
        assertDoesNotThrow(
                () -> pipeline.validate(testCase.legitimatePattern()),
                "Legitimate pattern should be accepted: %s\nDescription: %s\nRationale: %s".formatted(
                        testCase.legitimatePattern(),
                        testCase.description(),
                        testCase.acceptanceRationale())
        );

        // And: No security events should be recorded for legitimate patterns
        assertEquals(initialEventCount, eventCounter.getTotalCount(),
                "No security events should be recorded for legitimate pattern: %s".formatted(
                        testCase.getCompactSummary()));
    }

    /**
     * Additional test to verify the pattern can be validated multiple times
     * (testing for any state issues in the pipeline).
     */
    @ParameterizedTest
    @ArgumentsSource(LegitimatePathPatternsDatabase.ArgumentsProvider.class)
    @DisplayName("Legitimate patterns should be consistently accepted on multiple validations")
    void shouldConsistentlyAcceptLegitimatePatterns(LegitimateTestCase testCase) {
        // Validate the same pattern multiple times to ensure consistency
        for (int i = 0; i < 3; i++) {
            assertDoesNotThrow(
                    () -> pipeline.validate(testCase.legitimatePattern()),
                    "Pattern should be consistently accepted on validation #%d: %s".formatted(
                            i + 1, testCase.legitimatePattern())
            );
        }
    }
}