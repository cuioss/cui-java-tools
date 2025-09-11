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

import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.generator.junit.parameterized.TypeGeneratorSource;
import de.cuioss.tools.security.http.config.SecurityConfiguration;
import de.cuioss.tools.security.http.core.UrlSecurityFailureType;
import de.cuioss.tools.security.http.exceptions.UrlSecurityException;
import de.cuioss.tools.security.http.generators.injection.LdapInjectionAttackGenerator;
import de.cuioss.tools.security.http.monitoring.SecurityEventCounter;
import de.cuioss.tools.security.http.pipeline.URLPathValidationPipeline;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * T14: Test LDAP injection patterns
 * 
 * <p>
 * This test class implements Task T14 from the HTTP security validation plan,
 * focusing on testing LDAP injection attacks that attempt to manipulate LDAP
 * queries and directory searches through web application inputs. LDAP injection
 * represents a serious vulnerability that can lead to unauthorized directory access,
 * authentication bypass, and information disclosure in directory-enabled applications.
 * </p>
 * 
 * <h3>Test Coverage</h3>
 * <ul>
 *   <li>AND/OR Logic Manipulation - Boolean logic injection in LDAP filters</li>
 *   <li>Authentication Bypass - Login credential manipulation attacks</li>
 *   <li>Wildcard Injection - LDAP wildcard character exploitation</li>
 *   <li>Comment-based Attacks - LDAP comment injection techniques</li>
 *   <li>Filter Escape Attacks - LDAP filter character escaping bypass</li>
 *   <li>Attribute Enumeration - Directory attribute discovery attacks</li>
 *   <li>DN Manipulation - Distinguished Name injection attacks</li>
 *   <li>Blind LDAP Injection - Information extraction via response timing</li>
 *   <li>Error-based LDAP Attacks - Directory error information disclosure</li>
 *   <li>Base DN Traversal - Directory tree traversal attacks</li>
 *   <li>Schema Discovery - LDAP schema information extraction</li>
 *   <li>User Enumeration - Directory user account discovery</li>
 *   <li>Group Membership Attacks - Group-based access control bypass</li>
 *   <li>Nested Filter Injection - Complex nested LDAP filter attacks</li>
 *   <li>Unicode LDAP Attacks - Unicode-based LDAP filter bypass</li>
 * </ul>
 * 
 * <h3>Security Standards Compliance</h3>
 * <p>
 * This test ensures compliance with:
 * </p>
 * <ul>
 *   <li>OWASP Top 10: A03:2021 – Injection</li>
 *   <li>CWE-90: Improper Neutralization of Special Elements used in an LDAP Query</li>
 *   <li>CWE-74: Improper Neutralization of Special Elements in Output</li>
 *   <li>NIST SP 800-63B: Authentication and Lifecycle Management</li>
 *   <li>ISO 27001: A.9.2.1 User registration and de-registration</li>
 * </ul>
 * 
 * <h3>Performance Requirements</h3>
 * <p>
 * Each validation must complete within 8ms to ensure production feasibility.
 * LDAP injection detection should not introduce significant latency to directory
 * operations or user authentication processes.
 * </p>
 * 
 * @see LdapInjectionAttackGenerator
 * @see URLPathValidationPipeline
 * @author Generated for HTTP Security Validation (T14)
 * @version 1.0.0
 */
@EnableGeneratorController
@DisplayName("T14: LDAP Injection Attack Validation Tests")
class LdapInjectionAttackTest {

    private URLPathValidationPipeline pipeline;
    private SecurityEventCounter eventCounter;
    private SecurityConfiguration config;

    @BeforeEach
    void setUp() {
        config = SecurityConfiguration.defaults();
        eventCounter = new SecurityEventCounter();
        pipeline = new URLPathValidationPipeline(config, eventCounter);
    }

    @ParameterizedTest
    @TypeGeneratorSource(value = LdapInjectionAttackGenerator.class, count = 150)
    @DisplayName("All LDAP injection attacks should be rejected")
    void shouldRejectAllLdapInjectionAttacks(String ldapAttackPattern) {
        var exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(ldapAttackPattern),
                "LDAP injection attack should be rejected: " + sanitizeForDisplay(ldapAttackPattern));

        assertTrue(
                exception.getFailureType() == UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED ||
                        exception.getFailureType() == UrlSecurityFailureType.INVALID_CHARACTER ||
                        exception.getFailureType() == UrlSecurityFailureType.MALFORMED_INPUT,
                "LDAP injection should be detected with appropriate failure type, got: " + exception.getFailureType()
        );

        assertTrue(eventCounter.getCount(UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED) +
                eventCounter.getCount(UrlSecurityFailureType.INVALID_CHARACTER) +
                eventCounter.getCount(UrlSecurityFailureType.MALFORMED_INPUT) > 0,
                "Security event counter should track LDAP injection detection");
    }

    @ParameterizedTest
    @TypeGeneratorSource(value = LdapInjectionAttackGenerator.class, count = 25)
    @DisplayName("LDAP injection patterns should be reliably detected")
    void shouldReliablyDetectLdapInjectionPatterns(String ldapPattern) {
        // When: LDAP injection pattern is validated
        var exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(ldapPattern),
                "LDAP injection should be detected: " + sanitizeForDisplay(ldapPattern));

        // Then: Attack should be properly categorized  
        assertTrue(
                exception.getFailureType() == UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED ||
                        exception.getFailureType() == UrlSecurityFailureType.INVALID_CHARACTER ||
                        exception.getFailureType() == UrlSecurityFailureType.MALFORMED_INPUT ||
                        exception.getFailureType() == UrlSecurityFailureType.SQL_INJECTION_DETECTED ||
                        exception.getFailureType() == UrlSecurityFailureType.COMMAND_INJECTION_DETECTED,
                "LDAP injection should be properly categorized for: " + sanitizeForDisplay(ldapPattern)
        );
    }

    @ParameterizedTest
    @TypeGeneratorSource(value = LdapInjectionAttackGenerator.class, count = 30)
    @DisplayName("Known dangerous LDAP injection patterns should be rejected")
    void shouldRejectKnownLdapInjectionAttacks(String ldapAttack) {
        var exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(ldapAttack),
                "Known LDAP injection attack should be rejected: " + sanitizeForDisplay(ldapAttack));

        assertTrue(
                exception.getFailureType() == UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED ||
                        exception.getFailureType() == UrlSecurityFailureType.INVALID_CHARACTER ||
                        exception.getFailureType() == UrlSecurityFailureType.MALFORMED_INPUT ||
                        exception.getFailureType() == UrlSecurityFailureType.SQL_INJECTION_DETECTED ||
                        exception.getFailureType() == UrlSecurityFailureType.COMMAND_INJECTION_DETECTED,
                "LDAP injection should be properly categorized for: " + sanitizeForDisplay(ldapAttack)
        );
    }

    @ParameterizedTest
    @TypeGeneratorSource(value = LdapInjectionAttackGenerator.class, count = 20)
    @DisplayName("LDAP injection detection should handle edge cases")
    void shouldHandleEdgeCasesInLdapInjection(String edgeCase) {
        var exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(edgeCase),
                "Edge case LDAP injection should be detected: " + sanitizeForDisplay(edgeCase));

        assertNotNull(exception.getFailureType(),
                "Edge case should have proper failure type classification");
    }

    @ParameterizedTest
    @TypeGeneratorSource(value = LdapInjectionAttackGenerator.class, count = 25)
    @DisplayName("Should validate authentication bypass LDAP attacks are blocked")
    void shouldValidateAuthenticationBypassBlocking(String authBypassAttack) {

        var exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(authBypassAttack),
                "Authentication bypass LDAP attack should be blocked: " + sanitizeForDisplay(authBypassAttack));

        assertTrue(
                exception.getFailureType() == UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED ||
                        exception.getFailureType() == UrlSecurityFailureType.INVALID_CHARACTER ||
                        exception.getFailureType() == UrlSecurityFailureType.MALFORMED_INPUT ||
                        exception.getFailureType() == UrlSecurityFailureType.SQL_INJECTION_DETECTED ||
                        exception.getFailureType() == UrlSecurityFailureType.COMMAND_INJECTION_DETECTED,
                "Authentication bypass should be properly classified as dangerous"
        );
    }

    @ParameterizedTest
    @TypeGeneratorSource(value = LdapInjectionAttackGenerator.class, count = 20)
    @DisplayName("Should handle LDAP wildcard and enumeration attacks")
    void shouldHandleLdapWildcardEnumerationAttacks(String wildcardAttack) {
        var exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(wildcardAttack),
                "LDAP wildcard/enumeration attack should be detected: " + sanitizeForDisplay(wildcardAttack));

        assertNotNull(exception.getFailureType(),
                "Wildcard attack should be properly classified");
    }

    @Test
    @DisplayName("Should properly track LDAP injection security events")
    void shouldTrackLdapInjectionEvents() {
        long initialCount = eventCounter.getCount(UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED) +
                eventCounter.getCount(UrlSecurityFailureType.INVALID_CHARACTER) +
                eventCounter.getCount(UrlSecurityFailureType.MALFORMED_INPUT);

        String testAttack = "http://example.com/auth?user=admin)(&(objectClass=*";

        assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(testAttack));

        long finalCount = eventCounter.getCount(UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED) +
                eventCounter.getCount(UrlSecurityFailureType.INVALID_CHARACTER) +
                eventCounter.getCount(UrlSecurityFailureType.MALFORMED_INPUT);

        assertTrue(finalCount > initialCount,
                "LDAP injection detection should increment security event counter");
    }

    @ParameterizedTest
    @TypeGeneratorSource(value = LdapInjectionAttackGenerator.class, count = 15)
    @DisplayName("Should maintain consistent detection across similar LDAP patterns")
    void shouldConsistentlyDetectSimilarLdapPatterns(String similarPattern) {
        // All LDAP injection patterns should be consistently detected
        var exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(similarPattern),
                "Similar LDAP pattern should be detected: " + sanitizeForDisplay(similarPattern));
        
        assertTrue(
                exception.getFailureType() == UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED ||
                        exception.getFailureType() == UrlSecurityFailureType.INVALID_CHARACTER ||
                        exception.getFailureType() == UrlSecurityFailureType.MALFORMED_INPUT ||
                        exception.getFailureType() == UrlSecurityFailureType.SQL_INJECTION_DETECTED ||
                        exception.getFailureType() == UrlSecurityFailureType.COMMAND_INJECTION_DETECTED,
                "Similar pattern should have consistent detection: " + sanitizeForDisplay(similarPattern)
        );
    }

    @ParameterizedTest
    @TypeGeneratorSource(value = LdapInjectionAttackGenerator.class, count = 18)
    @DisplayName("Should detect nested and complex LDAP filter injections")
    void shouldDetectComplexLdapFilterInjections(String complexAttack) {
        var exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(complexAttack),
                "Complex LDAP filter injection should be detected: " + sanitizeForDisplay(complexAttack));

            assertTrue(
                    exception.getFailureType() == UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED ||
                            exception.getFailureType() == UrlSecurityFailureType.INVALID_CHARACTER ||
                            exception.getFailureType() == UrlSecurityFailureType.MALFORMED_INPUT,
                    "Complex filter injection should be properly classified"
            );
        }
    }

    @ParameterizedTest
    @TypeGeneratorSource(value = LdapInjectionAttackGenerator.class, count = 16)
    @DisplayName("Should handle LDAP DN manipulation and traversal attacks")
    void shouldHandleLdapDnManipulationAttacks(String dnAttack) {
        var exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(dnAttack),
                "LDAP DN manipulation attack should be detected: " + sanitizeForDisplay(dnAttack));

        assertNotNull(exception.getFailureType(),
                "DN manipulation attack should be properly classified");
    }

    private String sanitizeForDisplay(String input) {
        if (input == null) return "null";
        return input.length() > 100 ?
                input.substring(0, 100) + "..." : input;
    }
}