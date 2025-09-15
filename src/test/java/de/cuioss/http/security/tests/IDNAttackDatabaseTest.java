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
import de.cuioss.http.security.database.IDNAttackDatabase;
import de.cuioss.http.security.exceptions.UrlSecurityException;
import de.cuioss.http.security.monitoring.SecurityEventCounter;
import de.cuioss.http.security.pipeline.HTTPBodyValidationPipeline;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * IDN (Internationalized Domain Name) Attack Database Tests using structured attack database.
 *
 * <p><strong>COMPREHENSIVE IDN ATTACK DATABASE TESTING:</strong> This test class validates
 * Internationalized Domain Name attack patterns that exploit IDN processing vulnerabilities,
 * including punycode encoding bypass, mixed script attacks, and homograph domain spoofing.</p>
 *
 * <p>Tests various IDN attack vectors that can bypass domain validation, create phishing
 * domains, and exploit Unicode normalization vulnerabilities in domain name processing.</p>
 *
 * <h3>Attack Categories Tested</h3>
 * <ul>
 *   <li><strong>Punycode Bypass</strong> - Malformed punycode to bypass filters</li>
 *   <li><strong>Mixed Script Domains</strong> - Combining character sets in domain names</li>
 *   <li><strong>Homograph Domains</strong> - Visually similar characters in domain spoofing</li>
 *   <li><strong>Unicode Normalization</strong> - Exploiting normalization differences</li>
 *   <li><strong>IDN Encoding Bypass</strong> - Various encoding bypass techniques</li>
 * </ul>
 *
 * @author Claude Code Generator
 * @since 2.5
 */
@DisplayName("IDN Attack Database Tests")
class IDNAttackDatabaseTest {

    private HTTPBodyValidationPipeline pipeline;
    private SecurityEventCounter eventCounter;

    @BeforeEach
    void setUp() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .allowHighBitCharacters(true)  // Allow Unicode/IDN characters
                .failOnSuspiciousPatterns(true)  // Enable suspicious pattern detection
                .build();
        eventCounter = new SecurityEventCounter();
        pipeline = new HTTPBodyValidationPipeline(config, eventCounter);
    }

    /**
     * Parameterized test that validates all IDN attack patterns from the database.
     * Each test case includes comprehensive documentation and expected failure types.
     *
     * @param testCase AttackTestCase containing IDN attack, expected failure type, and documentation
     */
    @ParameterizedTest
    @ArgumentsSource(IDNAttackDatabase.ArgumentsProvider.class)
    @DisplayName("IDN attack patterns should be rejected with correct failure types")
    void shouldRejectIDNAttacksWithCorrectFailureTypes(AttackTestCase testCase) {
        // Given: An IDN attack test case with expected failure type
        long initialEventCount = eventCounter.getTotalCount();

        // When: Attempting to validate the malicious IDN pattern
        String attackRejectionMessage = "IDN attack should be rejected: %s\nAttack Description: %s\nDetection Rationale: %s".formatted(
                testCase.attackString(), testCase.attackDescription(), testCase.detectionRationale());
        var exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(testCase.attackString()),
                attackRejectionMessage);

        // Then: The validation should fail with the expected security failure type
        String failureTypeMessage = "Expected failure type %s for IDN attack: %s\nRationale: %s".formatted(
                testCase.expectedFailureType(), testCase.attackString(), testCase.detectionRationale());
        assertEquals(testCase.expectedFailureType(), exception.getFailureType(), failureTypeMessage);

        // And: Original malicious input should be preserved
        assertEquals(testCase.attackString(), exception.getOriginalInput(),
                "Original IDN attack string should be preserved in exception");

        // And: Security event should be recorded
        assertTrue(eventCounter.getTotalCount() > initialEventCount,
                "Security event should be recorded for IDN attack: %s".formatted(testCase.getCompactSummary()));
    }
}