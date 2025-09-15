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
import de.cuioss.http.security.database.IPv6AttackDatabase;
import de.cuioss.http.security.exceptions.UrlSecurityException;
import de.cuioss.http.security.monitoring.SecurityEventCounter;
import de.cuioss.http.security.pipeline.URLPathValidationPipeline;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * IPv6 Attack Database Tests using structured attack database.
 *
 * <p><strong>COMPREHENSIVE IPv6 ATTACK DATABASE TESTING:</strong> This test class validates
 * IPv6 protocol attack patterns that exploit IPv6 address parsing vulnerabilities,
 * including IPv4-mapped bypass attacks, scope injection, and malformed address exploitation.</p>
 *
 * <p>Tests various IPv6 attack vectors that can bypass network filtering, exploit
 * dual-stack configurations, and abuse IPv6 address parsing inconsistencies across
 * different systems and libraries.</p>
 *
 * <h3>Attack Categories Tested</h3>
 * <ul>
 *   <li><strong>IPv4-Mapped Bypass</strong> - Using IPv4-mapped addresses to bypass filters</li>
 *   <li><strong>Scope Injection</strong> - Zone ID and scope identifier abuse</li>
 *   <li><strong>Address Compression</strong> - Zero compression parsing exploits</li>
 *   <li><strong>Embedded IPv4</strong> - Mixed IPv4/IPv6 notation abuse</li>
 *   <li><strong>Malformed Addresses</strong> - Invalid but parseable IPv6 formats</li>
 * </ul>
 *
 * @author Claude Code Generator
 * @since 2.5
 */
@DisplayName("IPv6 Attack Database Tests")
class IPv6AttackDatabaseTest {

    private URLPathValidationPipeline pipeline;
    private SecurityEventCounter eventCounter;

    @BeforeEach
    void setUp() {
        SecurityConfiguration config = SecurityConfiguration.defaults();
        eventCounter = new SecurityEventCounter();
        pipeline = new URLPathValidationPipeline(config, eventCounter);
    }

    /**
     * Parameterized test that validates all IPv6 attack patterns from the database.
     * Each test case includes comprehensive documentation and expected failure types.
     *
     * @param testCase AttackTestCase containing IPv6 attack, expected failure type, and documentation
     */
    @ParameterizedTest
    @ArgumentsSource(IPv6AttackDatabase.ArgumentsProvider.class)
    @DisplayName("IPv6 attack patterns should be rejected with correct failure types")
    void shouldRejectIPv6AttacksWithCorrectFailureTypes(AttackTestCase testCase) {
        // Given: An IPv6 attack test case with expected failure type
        long initialEventCount = eventCounter.getTotalCount();

        // When: Attempting to validate the malicious IPv6 pattern
        String attackRejectionMessage = "IPv6 attack should be rejected: %s\nAttack Description: %s\nDetection Rationale: %s".formatted(
                testCase.attackString(), testCase.attackDescription(), testCase.detectionRationale());
        var exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(testCase.attackString()),
                attackRejectionMessage);

        // Then: The validation should fail with the expected security failure type
        String failureTypeMessage = "Expected failure type %s for IPv6 attack: %s\nRationale: %s".formatted(
                testCase.expectedFailureType(), testCase.attackString(), testCase.detectionRationale());
        assertEquals(testCase.expectedFailureType(), exception.getFailureType(), failureTypeMessage);

        // And: Original malicious input should be preserved
        assertEquals(testCase.attackString(), exception.getOriginalInput(),
                "Original IPv6 attack string should be preserved in exception");

        // And: Security event should be recorded
        assertTrue(eventCounter.getTotalCount() > initialEventCount,
                "Security event should be recorded for IPv6 attack: %s".formatted(testCase.getCompactSummary()));
    }
}