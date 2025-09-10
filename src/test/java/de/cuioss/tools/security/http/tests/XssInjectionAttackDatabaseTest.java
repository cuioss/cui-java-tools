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
import de.cuioss.tools.security.http.database.AttackTestCase;
import de.cuioss.tools.security.http.database.XssInjectionAttackDatabase;
import de.cuioss.tools.security.http.exceptions.UrlSecurityException;
import de.cuioss.tools.security.http.monitoring.SecurityEventCounter;
import de.cuioss.tools.security.http.pipeline.HTTPBodyValidationPipeline;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * XSS Injection Attack Database Tests using structured attack database.
 *
 * <p><strong>COMPREHENSIVE XSS ATTACK DATABASE TESTING:</strong> This test class validates
 * Cross-Site Scripting (XSS) attack patterns covering reflected, stored, and DOM-based
 * XSS vectors with comprehensive encoding bypass techniques and filter evasion methods.</p>
 *
 * <p>Tests various XSS attack vectors including HTML tag injection, JavaScript execution,
 * event handler abuse, CSS-based attacks, and advanced obfuscation techniques used
 * to bypass web application firewalls and input sanitization.</p>
 *
 * <h3>XSS Attack Categories Tested</h3>
 * <ul>
 *   <li><strong>Script Tag Injection</strong> - Direct script element insertion</li>
 *   <li><strong>Event Handler XSS</strong> - HTML event attribute exploitation</li>
 *   <li><strong>JavaScript Protocol</strong> - javascript: URL scheme attacks</li>
 *   <li><strong>CSS-based XSS</strong> - Cascading Style Sheet injection</li>
 *   <li><strong>Encoding Bypass</strong> - HTML entity, URL, and Unicode encoding</li>
 *   <li><strong>Filter Evasion</strong> - WAF and sanitization bypass techniques</li>
 *   <li><strong>DOM-based XSS</strong> - Client-side DOM manipulation attacks</li>
 *   <li><strong>Polyglot Attacks</strong> - Multi-context XSS payloads</li>
 * </ul>
 *
 * @author Claude Code Generator
 * @since 2.5
 */
@DisplayName("XSS Injection Attack Database Tests")
class XssInjectionAttackDatabaseTest {

    private HTTPBodyValidationPipeline pipeline;
    private SecurityEventCounter eventCounter;

    @BeforeEach
    void setUp() {
        SecurityConfiguration config = SecurityConfiguration.defaults();
        eventCounter = new SecurityEventCounter();
        pipeline = new HTTPBodyValidationPipeline(config, eventCounter);
    }

    /**
     * Parameterized test that validates all XSS injection attack patterns from the database.
     * Each test case includes comprehensive documentation and expected failure types.
     *
     * @param testCase AttackTestCase containing XSS attack, expected failure type, and documentation
     */
    @ParameterizedTest
    @ArgumentsSource(XssInjectionAttackDatabase.ArgumentsProvider.class)
    @DisplayName("XSS injection attack patterns should be rejected with correct failure types")
    void shouldRejectXssInjectionAttacksWithCorrectFailureTypes(AttackTestCase testCase) {
        // Given: An XSS injection attack test case with expected failure type
        long initialEventCount = eventCounter.getTotalCount();

        // When: Attempting to validate the malicious XSS pattern
        String attackRejectionMessage = "XSS injection attack should be rejected: %s\nAttack Description: %s\nDetection Rationale: %s".formatted(
                testCase.attackString(), testCase.attackDescription(), testCase.detectionRationale());
        var exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(testCase.attackString()),
                attackRejectionMessage);

        // Then: The validation should fail with the expected security failure type
        String failureTypeMessage = "Expected failure type %s for XSS attack: %s\nRationale: %s".formatted(
                testCase.expectedFailureType(), testCase.attackString(), testCase.detectionRationale());
        assertEquals(testCase.expectedFailureType(), exception.getFailureType(), failureTypeMessage);

        // And: Original malicious input should be preserved
        assertEquals(testCase.attackString(), exception.getOriginalInput(),
                "Original XSS attack string should be preserved in exception");

        // And: Security event should be recorded
        assertTrue(eventCounter.getTotalCount() > initialEventCount,
                "Security event should be recorded for XSS attack: %s".formatted(testCase.getCompactSummary()));
    }
}