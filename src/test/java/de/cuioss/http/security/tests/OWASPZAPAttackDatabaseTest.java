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
import de.cuioss.http.security.database.OWASPZAPAttackDatabase;
import de.cuioss.http.security.exceptions.UrlSecurityException;
import de.cuioss.http.security.monitoring.SecurityEventCounter;
import de.cuioss.http.security.pipeline.URLPathValidationPipeline;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for OWASP ZAP Active Scan Attack Database.
 *
 * <p><strong>COMPREHENSIVE ZAP ATTACK TESTING:</strong> This test class validates that all
 * OWASP ZAP active scan attack patterns are properly detected and rejected by the security
 * validation pipeline. Each test case represents an actual attack pattern used by ZAP
 * during security assessments.</p>
 *
 * <p>ZAP (Zed Attack Proxy) is one of the most widely used web application security testing
 * tools, maintained by OWASP. Its active scan rules are continuously updated based on
 * emerging threats and have been battle-tested against millions of web applications.</p>
 *
 * <h3>Test Coverage</h3>
 * <ul>
 *   <li><strong>Path Traversal</strong>: Multiple encoding variants</li>
 *   <li><strong>Directory Browsing</strong>: Directory listing attempts</li>
 *   <li><strong>Local File Inclusion</strong>: Protocol handler attacks</li>
 *   <li><strong>HTTP Splitting</strong>: CRLF injection patterns</li>
 *   <li><strong>Encoding Attacks</strong>: Unicode and mixed encoding</li>
 * </ul>
 *
 * @author Claude Code Generator
 * @since 2.5
 */
@DisplayName("OWASP ZAP Active Scan Attack Database Tests")
class OWASPZAPAttackDatabaseTest {

    private URLPathValidationPipeline pipeline;
    private SecurityEventCounter eventCounter;

    @BeforeEach
    void setUp() {
        SecurityConfiguration config = SecurityConfiguration.defaults();
        eventCounter = new SecurityEventCounter();
        pipeline = new URLPathValidationPipeline(config, eventCounter);
    }

    /**
     * Parameterized test that validates all OWASP ZAP attack patterns from the database.
     * Each test case includes comprehensive documentation and expected failure types.
     *
     * @param testCase AttackTestCase containing attack string, expected failure type, and documentation
     */
    @ParameterizedTest
    @ArgumentsSource(OWASPZAPAttackDatabase.ArgumentsProvider.class)
    @DisplayName("OWASP ZAP active scan patterns should be rejected with correct failure types")
    void shouldRejectZAPAttacksWithCorrectFailureTypes(AttackTestCase testCase) {
        // Given: A ZAP active scan attack test case with expected failure type
        long initialEventCount = eventCounter.getTotalCount();

        // When: Attempting to validate the malicious pattern
        String attackRejectionMessage = "ZAP attack should be rejected: %s\nAttack Description: %s\nDetection Rationale: %s".formatted(
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