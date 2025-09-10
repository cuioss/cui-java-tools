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
import de.cuioss.tools.security.http.database.ApacheCVEAttackDatabase;
import de.cuioss.tools.security.http.database.AttackTestCase;
import de.cuioss.tools.security.http.exceptions.UrlSecurityException;
import de.cuioss.tools.security.http.monitoring.SecurityEventCounter;
import de.cuioss.tools.security.http.pipeline.URLPathValidationPipeline;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Updated Apache CVE Attack Tests using new AttackDatabase structure.
 *
 * <p><strong>COMPREHENSIVE CVE DATABASE TESTING:</strong> This test class demonstrates the new
 * approach to security testing using structured attack databases. Each test case contains
 * detailed attack documentation, expected failure types, and comprehensive security context.</p>
 *
 * <p>This replaces the previous generator-based approach with a more structured database
 * approach that provides better traceability, documentation, and specific failure type testing.</p>
 *
 * <h3>Key Improvements</h3>
 * <ul>
 *   <li><strong>Detailed Test Context</strong>: Each attack includes comprehensive documentation</li>
 *   <li><strong>Specific Failure Testing</strong>: Tests verify expected UrlSecurityFailureType</li>
 *   <li><strong>Enhanced Debugging</strong>: Clear error messages with attack details</li>
 *   <li><strong>Individual Test Access</strong>: Public constants enable specific test targeting</li>
 * </ul>
 *
 * @author Claude Code Generator
 * @since 2.5
 */
@DisplayName("Apache CVE Attack Database Tests")
class ApacheCVEAttackDatabaseTest {

    private URLPathValidationPipeline pipeline;
    private SecurityEventCounter eventCounter;

    @BeforeEach
    void setUp() {
        SecurityConfiguration config = SecurityConfiguration.defaults();
        eventCounter = new SecurityEventCounter();
        pipeline = new URLPathValidationPipeline(config, eventCounter);
    }

    /**
     * Parameterized test that validates all Apache CVE attack patterns from the database.
     * Each test case includes comprehensive documentation and expected failure types.
     *
     * @param testCase AttackTestCase containing attack string, expected failure type, and documentation
     */
    @ParameterizedTest
    @ArgumentsSource(ApacheCVEAttackDatabase.ArgumentsProvider.class)
    @DisplayName("Apache CVE attack patterns should be rejected with correct failure types")
    void shouldRejectApacheCVEAttacksWithCorrectFailureTypes(AttackTestCase testCase) {
        // Given: An Apache CVE attack test case with expected failure type
        long initialEventCount = eventCounter.getTotalCount();

        // When: Attempting to validate the malicious pattern
        String attackRejectionMessage = "Apache CVE attack should be rejected: %s\nAttack Description: %s\nDetection Rationale: %s".formatted(
                testCase.attackString(), testCase.attackDescription(), testCase.detectionRationale());
        var exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(testCase.attackString()),
                attackRejectionMessage);

        // Then: The validation should fail with the expected security failure type
        String failureTypeMessage = "Expected failure type %s for attack: %s\nRationale: %s".formatted(
                testCase.expectedFailureType(), testCase.attackString(), testCase.detectionRationale());
        assertEquals(testCase.expectedFailureType(), exception.getFailureType(), failureTypeMessage);

        // And: Original malicious input should be preserved
        assertEquals(testCase.attackString(), exception.getOriginalInput(),
                "Original attack string should be preserved in exception");

        // And: Security event should be recorded
        assertTrue(eventCounter.getTotalCount() > initialEventCount,
                "Security event should be recorded for attack: %s".formatted(testCase.getCompactSummary()));
    }
}