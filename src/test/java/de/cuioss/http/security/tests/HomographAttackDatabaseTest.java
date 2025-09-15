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
import de.cuioss.http.security.database.AttackTestCase;
import de.cuioss.http.security.database.HomographAttackDatabase;
import de.cuioss.http.security.exceptions.UrlSecurityException;
import de.cuioss.http.security.monitoring.SecurityEventCounter;
import de.cuioss.http.security.pipeline.URLPathValidationPipeline;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Homograph Attack Database Tests using structured attack database.
 *
 * <p><strong>COMPREHENSIVE UNICODE HOMOGRAPH DATABASE TESTING:</strong> This test class validates
 * Unicode homograph attack patterns that exploit visual character similarity across different
 * writing systems to bypass security filters while appearing legitimate to human users.</p>
 *
 * <p>Tests Unicode homographs from Cyrillic, Greek, Mathematical, Fullwidth, Armenian,
 * and Georgian scripts that are visually identical or nearly identical to Latin characters
 * but have different Unicode code points.</p>
 *
 * <h3>Attack Categories Tested</h3>
 * <ul>
 *   <li><strong>Cyrillic Homographs</strong> - а, о, р, с, е, х → a, o, p, c, e, x</li>
 *   <li><strong>Greek Homographs</strong> - α, ο, ρ, υ → a, o, p, u</li>
 *   <li><strong>Mathematical Script</strong> - Unicode Mathematical Bold variants</li>
 *   <li><strong>Fullwidth Characters</strong> - East Asian typography variants</li>
 *   <li><strong>Mixed Script Attacks</strong> - Combinations across character sets</li>
 * </ul>
 *
 * @author Claude Code Generator
 * @since 2.5
 */
@DisplayName("Homograph Attack Database Tests")
class HomographAttackDatabaseTest {

    private URLPathValidationPipeline pipeline;
    private SecurityEventCounter eventCounter;

    @BeforeEach
    void setUp() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .allowHighBitCharacters(true)  // Allow Unicode characters for homograph detection
                .failOnSuspiciousPatterns(true)  // Enable suspicious pattern detection
                .build();
        eventCounter = new SecurityEventCounter();
        pipeline = new URLPathValidationPipeline(config, eventCounter);
    }

    /**
     * Parameterized test that validates all Unicode homograph attack patterns from the database.
     * Each test case includes comprehensive documentation and expected failure types.
     *
     * @param testCase AttackTestCase containing homograph attack, expected failure type, and documentation
     */
    @ParameterizedTest
    @ArgumentsSource(HomographAttackDatabase.ArgumentsProvider.class)
    @DisplayName("Unicode homograph attack patterns should be rejected with correct failure types")
    void shouldRejectHomographAttacksWithCorrectFailureTypes(AttackTestCase testCase) {
        // Given: A Unicode homograph attack test case with expected failure type
        long initialEventCount = eventCounter.getTotalCount();

        // When: Attempting to validate the malicious homograph pattern
        String attackRejectionMessage = "Homograph attack should be rejected: %s\nAttack Description: %s\nDetection Rationale: %s".formatted(
                testCase.attackString(), testCase.attackDescription(), testCase.detectionRationale());
        var exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(testCase.attackString()),
                attackRejectionMessage);

        // Then: The validation should fail with the expected security failure type
        String failureTypeMessage = "Expected failure type %s for homograph attack: %s\nRationale: %s".formatted(
                testCase.expectedFailureType(), testCase.attackString(), testCase.detectionRationale());
        assertEquals(testCase.expectedFailureType(), exception.getFailureType(), failureTypeMessage);

        // And: Original malicious input should be preserved
        assertEquals(testCase.attackString(), exception.getOriginalInput(),
                "Original homograph attack string should be preserved in exception");

        // And: Security event should be recorded
        assertTrue(eventCounter.getTotalCount() > initialEventCount,
                "Security event should be recorded for homograph attack: %s".formatted(testCase.getCompactSummary()));
    }
}