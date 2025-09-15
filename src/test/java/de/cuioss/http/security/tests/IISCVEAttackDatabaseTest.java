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
import de.cuioss.http.security.database.IISCVEAttackDatabase;
import de.cuioss.http.security.exceptions.UrlSecurityException;
import de.cuioss.http.security.monitoring.SecurityEventCounter;
import de.cuioss.http.security.pipeline.URLPathValidationPipeline;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * IIS CVE Attack Database Tests using structured attack database.
 *
 * <p><strong>COMPREHENSIVE IIS CVE DATABASE TESTING:</strong> This test class validates
 * Microsoft IIS CVE exploit patterns that target specific vulnerabilities in Internet
 * Information Services across different versions and configurations.</p>
 *
 * <p>Tests documented CVE exploits for IIS that include directory traversal bypasses,
 * buffer overflow attempts, request smuggling, and various parsing vulnerabilities
 * specific to Microsoft's web server implementation.</p>
 *
 * <h3>CVE Categories Tested</h3>
 * <ul>
 *   <li><strong>Path Traversal CVEs</strong> - Directory escapes specific to IIS</li>
 *   <li><strong>Buffer Overflow CVEs</strong> - Memory corruption attack patterns</li>
 *   <li><strong>Request Smuggling CVEs</strong> - HTTP request parsing exploits</li>
 *   <li><strong>Authentication Bypass CVEs</strong> - IIS authentication vulnerabilities</li>
 *   <li><strong>Remote Code Execution CVEs</strong> - RCE exploit patterns for IIS</li>
 * </ul>
 *
 * @author Claude Code Generator
 * @since 2.5
 */
@DisplayName("IIS CVE Attack Database Tests")
class IISCVEAttackDatabaseTest {

    private URLPathValidationPipeline pipeline;
    private SecurityEventCounter eventCounter;

    @BeforeEach
    void setUp() {
        SecurityConfiguration config = SecurityConfiguration.defaults();
        eventCounter = new SecurityEventCounter();
        pipeline = new URLPathValidationPipeline(config, eventCounter);
    }

    /**
     * Parameterized test that validates all IIS CVE attack patterns from the database.
     * Each test case includes comprehensive documentation and expected failure types.
     *
     * @param testCase AttackTestCase containing IIS CVE attack, expected failure type, and documentation
     */
    @ParameterizedTest
    @ArgumentsSource(IISCVEAttackDatabase.ArgumentsProvider.class)
    @DisplayName("IIS CVE attack patterns should be rejected with correct failure types")
    void shouldRejectIISCVEAttacksWithCorrectFailureTypes(AttackTestCase testCase) {
        // Given: An IIS CVE attack test case with expected failure type
        long initialEventCount = eventCounter.getTotalCount();

        // When: Attempting to validate the malicious IIS CVE pattern
        String attackRejectionMessage = "IIS CVE attack should be rejected: %s\nAttack Description: %s\nDetection Rationale: %s".formatted(
                testCase.attackString(), testCase.attackDescription(), testCase.detectionRationale());
        var exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(testCase.attackString()),
                attackRejectionMessage);

        // Then: The validation should fail with the expected security failure type
        String failureTypeMessage = "Expected failure type %s for IIS CVE attack: %s\nRationale: %s".formatted(
                testCase.expectedFailureType(), testCase.attackString(), testCase.detectionRationale());
        assertEquals(testCase.expectedFailureType(), exception.getFailureType(), failureTypeMessage);

        // And: Original malicious input should be preserved
        assertEquals(testCase.attackString(), exception.getOriginalInput(),
                "Original IIS CVE attack string should be preserved in exception");

        // And: Security event should be recorded
        assertTrue(eventCounter.getTotalCount() > initialEventCount,
                "Security event should be recorded for IIS CVE attack: %s".formatted(testCase.getCompactSummary()));
    }
}