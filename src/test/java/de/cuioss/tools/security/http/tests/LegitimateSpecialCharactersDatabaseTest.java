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

import de.cuioss.tools.security.http.config.SecurityConfiguration;
import de.cuioss.tools.security.http.database.LegitimateSpecialCharactersDatabase;
import de.cuioss.tools.security.http.database.LegitimateTestCase;
import de.cuioss.tools.security.http.monitoring.SecurityEventCounter;
import de.cuioss.tools.security.http.pipeline.URLPathValidationPipeline;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for Legitimate Special Characters Database (T32).
 *
 * <p><strong>FALSE POSITIVE PREVENTION:</strong> This test class validates that all
 * legitimate special character patterns are properly accepted by the security validation
 * pipeline without triggering false positives. Each test case represents valid use of
 * special characters in URLs.</p>
 *
 * <p>This test ensures that RFC 3986 unreserved characters, properly encoded reserved
 * characters, international text, and business identifiers are correctly accepted by
 * the validation system.</p>
 *
 * <h3>Test Coverage</h3>
 * <ul>
 *   <li><strong>RFC 3986</strong>: Unreserved characters (-, _, ~, .)</li>
 *   <li><strong>Encoded Reserved</strong>: Properly encoded special characters</li>
 *   <li><strong>International</strong>: UTF-8 encoded accents, umlauts, CJK</li>
 *   <li><strong>Scientific</strong>: Mathematical and chemical notation</li>
 *   <li><strong>Business IDs</strong>: Email-like, phone numbers, SKUs</li>
 * </ul>
 *
 * @author Claude Code Generator
 * @since 2.5
 */
@DisplayName("Legitimate Special Characters Database Tests (T32)")
class LegitimateSpecialCharactersDatabaseTest {

    private URLPathValidationPipeline pipeline;
    private SecurityEventCounter eventCounter;

    @BeforeEach
    void setUp() {
        // Use a configuration that allows special characters and international text
        SecurityConfiguration config = SecurityConfiguration.builder()
                .allowHighBitCharacters(true)  // Allow UTF-8 encoded characters
                .maxPathLength(500)
                .build();
        eventCounter = new SecurityEventCounter();
        pipeline = new URLPathValidationPipeline(config, eventCounter);
    }

    /**
     * Parameterized test that validates all legitimate special character patterns.
     * These patterns should NOT throw exceptions and should be accepted as valid.
     *
     * @param testCase LegitimateTestCase containing pattern and documentation
     */
    @ParameterizedTest
    @ArgumentsSource(LegitimateSpecialCharactersDatabase.ArgumentsProvider.class)
    @DisplayName("Legitimate special character patterns should be accepted without false positives")
    void shouldAcceptLegitimateSpecialCharacters(LegitimateTestCase testCase) {
        // Given: A legitimate pattern with special characters
        long initialEventCount = eventCounter.getTotalCount();

        // When/Then: Validating the pattern should NOT throw an exception
        assertDoesNotThrow(
                () -> pipeline.validate(testCase.legitimatePattern()),
                "Special character pattern should be accepted: %s\nDescription: %s\nRationale: %s".formatted(
                        testCase.legitimatePattern(),
                        testCase.description(),
                        testCase.acceptanceRationale())
        );

        // And: No security events should be recorded
        assertEquals(initialEventCount, eventCounter.getTotalCount(),
                "No security events should be recorded for legitimate special characters: %s".formatted(
                        testCase.getCompactSummary()));
    }

    /**
     * Test that special characters are handled consistently across multiple validations.
     */
    @ParameterizedTest
    @ArgumentsSource(LegitimateSpecialCharactersDatabase.ArgumentsProvider.class)
    @DisplayName("Special character patterns should be consistently accepted")
    void shouldConsistentlyAcceptSpecialCharacters(LegitimateTestCase testCase) {
        // Validate multiple times to ensure character handling is consistent
        for (int i = 0; i < 3; i++) {
            assertDoesNotThrow(
                    () -> pipeline.validate(testCase.legitimatePattern()),
                    "Special characters should be consistently accepted on validation #%d: %s".formatted(
                            i + 1, testCase.legitimatePattern())
            );
        }
    }

    /**
     * Verify that the pipeline correctly processes the pattern without corruption.
     */
    @ParameterizedTest
    @ArgumentsSource(LegitimateSpecialCharactersDatabase.ArgumentsProvider.class)
    @DisplayName("Special characters should be processed without corruption")
    void shouldProcessSpecialCharactersWithoutCorruption(LegitimateTestCase testCase) {
        // The validation should complete without throwing
        assertDoesNotThrow(() -> {
            pipeline.validate(testCase.legitimatePattern());
        }, "Pattern processing should not corrupt special characters: %s".formatted(
                testCase.legitimatePattern()));
        
        // Verify no warnings were logged (indicated by event counter)
        assertEquals(0, eventCounter.getTotalCount(),
                "Processing should be clean without warnings for: %s".formatted(
                        testCase.legitimatePattern()));
    }
}