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
import de.cuioss.http.security.database.OWASPTop10AttackDatabase;
import de.cuioss.http.security.exceptions.UrlSecurityException;
import de.cuioss.http.security.monitoring.SecurityEventCounter;
import de.cuioss.http.security.pipeline.URLPathValidationPipeline;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * OWASP Top 10 Attack Database Tests using structured attack database.
 *
 * <p><strong>COMPREHENSIVE OWASP TOP 10 DATABASE TESTING:</strong> This test class validates
 * attack patterns from the OWASP Top 10 most critical web application security risks.
 * Tests include proven attack patterns for injection, broken authentication, sensitive
 * data exposure, and other critical vulnerability categories.</p>
 *
 * <p>This database contains 173+ proven OWASP attack patterns including UTF-8 overlong
 * encoding, double URL encoding, cross-site scripting, SQL injection, and other
 * well-documented attack vectors from OWASP security guidelines.</p>
 *
 * <h3>OWASP Top 10 Categories Tested</h3>
 * <ul>
 *   <li><strong>A01 Injection</strong> - SQL, NoSQL, command injection patterns</li>
 *   <li><strong>A02 Broken Authentication</strong> - Authentication bypass techniques</li>
 *   <li><strong>A03 Sensitive Data Exposure</strong> - Data disclosure patterns</li>
 *   <li><strong>A04 XML External Entities (XXE)</strong> - XML processing exploits</li>
 *   <li><strong>A05 Broken Access Control</strong> - Authorization bypass patterns</li>
 *   <li><strong>A06 Security Misconfiguration</strong> - Configuration exploit patterns</li>
 *   <li><strong>A07 Cross-Site Scripting (XSS)</strong> - XSS attack vectors</li>
 *   <li><strong>A08 Insecure Deserialization</strong> - Deserialization exploits</li>
 *   <li><strong>A09 Known Vulnerabilities</strong> - Component vulnerability patterns</li>
 *   <li><strong>A10 Insufficient Logging</strong> - Logging bypass techniques</li>
 * </ul>
 *
 * @author Claude Code Generator
 * @since 2.5
 */
@DisplayName("OWASP Top 10 Attack Database Tests")
class OWASPTop10AttackDatabaseTest {

    private URLPathValidationPipeline pipeline;
    private SecurityEventCounter eventCounter;

    @BeforeEach
    void setUp() {
        SecurityConfiguration config = SecurityConfiguration.defaults();
        eventCounter = new SecurityEventCounter();
        pipeline = new URLPathValidationPipeline(config, eventCounter);
    }

    /**
     * Parameterized test that validates all OWASP Top 10 attack patterns from the database.
     * Each test case includes comprehensive documentation and expected failure types.
     *
     * @param testCase AttackTestCase containing OWASP attack, expected failure type, and documentation
     */
    @ParameterizedTest
    @ArgumentsSource(OWASPTop10AttackDatabase.ArgumentsProvider.class)
    @DisplayName("OWASP Top 10 attack patterns should be rejected with correct failure types")
    void shouldRejectOWASPTop10AttacksWithCorrectFailureTypes(AttackTestCase testCase) {
        // Given: An OWASP Top 10 attack test case with expected failure type
        long initialEventCount = eventCounter.getTotalCount();

        // When: Attempting to validate the malicious OWASP pattern
        String attackRejectionMessage = "OWASP Top 10 attack should be rejected: %s\nAttack Description: %s\nDetection Rationale: %s".formatted(
                testCase.attackString(), testCase.attackDescription(), testCase.detectionRationale());
        var exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(testCase.attackString()),
                attackRejectionMessage);

        // Then: The validation should fail with the expected security failure type
        String failureTypeMessage = "Expected failure type %s for OWASP attack: %s\nRationale: %s".formatted(
                testCase.expectedFailureType(), testCase.attackString(), testCase.detectionRationale());
        assertEquals(testCase.expectedFailureType(), exception.getFailureType(), failureTypeMessage);

        // And: Original malicious input should be preserved
        assertEquals(testCase.attackString(), exception.getOriginalInput(),
                "Original OWASP attack string should be preserved in exception");

        // And: Security event should be recorded
        assertTrue(eventCounter.getTotalCount() > initialEventCount,
                "Security event should be recorded for OWASP attack: %s".formatted(testCase.getCompactSummary()));
    }
}