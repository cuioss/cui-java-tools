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
import de.cuioss.tools.security.http.generators.LdapInjectionAttackGenerator;
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
    @DisplayName("LDAP injection validation should maintain performance requirements")
    void shouldMaintainPerformanceWithLdapInjection(String ldapPattern) {
        long startTime = System.nanoTime();

        assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(ldapPattern));

        long duration = System.nanoTime() - startTime;
        long milliseconds = duration / 1_000_000;

        assertTrue(milliseconds < 8,
                "LDAP injection validation took %dms, should be < 8ms for pattern: %s".formatted(
                        milliseconds, sanitizeForDisplay(ldapPattern)));
    }

    @Test
    @DisplayName("Known dangerous LDAP injection patterns should be rejected")
    void shouldRejectKnownLdapInjectionAttacks() {
        String[] knownAttacks = {
                "http://example.com/auth?user=admin)(&(objectClass=*",
                "https://site.org/login?username=*)|(uid=admin",
                "http://app.com/search?query=test)(&(1=1",
                "https://api.com/user?name=user)|(objectClass=person)(&(uid=*",
                "http://test.com/ldap?filter=admin))%00",
                "https://secure.com/dir?search=*)|(cn=*",
                "http://domain.com/auth?login=*)(uid=*))(|(uid=*",
                "https://web.org/users?param=admin)(&(password=*)",
                "http://site.com/query?attr=*)|(objectClass=*",
                "https://app.org/directory?dn=cn=admin,dc=domain,dc=com)(&(objectClass=*",
                "http://example.org/search?name=admin\\29\\28uid=*",
                "https://test.com/filter?value=user\\2A\\29\\28objectClass=*",
                "http://app.com/ldap?base=../cn=admin,dc=domain,dc=com",
                "https://site.org/auth?user=admin)(&(objectClass=subschema",
                "http://domain.com/dir?query=a*)(&(objectClass=person)(uid=a*"
        };

        for (String attack : knownAttacks) {
            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Known LDAP injection attack should be rejected: " + sanitizeForDisplay(attack));

            assertTrue(
                    exception.getFailureType() == UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED ||
                            exception.getFailureType() == UrlSecurityFailureType.INVALID_CHARACTER ||
                            exception.getFailureType() == UrlSecurityFailureType.MALFORMED_INPUT,
                    "LDAP injection should be properly categorized for: " + sanitizeForDisplay(attack)
            );
        }
    }

    @Test
    @DisplayName("LDAP injection detection should handle edge cases")
    void shouldHandleEdgeCasesInLdapInjection() {
        String[] edgeCases = {
                "http://example.com/auth?user=admin%29%28%26%28objectClass%3D%2A",  // URL encoded )(&(objectClass=*
                "https://site.org/login?name=user%2A%29%7C%28uid%3Dadmin",        // URL encoded *)|(uid=admin
                "http://app.com/search?q=test%29%28%26%281%3D1",                  // URL encoded )(&(1=1
                "https://secure.com/dir?filter=admin%29%29%2500",                 // URL encoded ))%00
                "http://domain.com/ldap?param=user%5C29%5C28objectClass%3D%2A",   // URL encoded \29\28objectClass=*
                "https://test.org/auth?login=admin%u0029%u0028uid%3D%2A",         // Unicode encoded )&(uid=*
                "http://site.com/query?value=test%C0%A9%C0%A8objectClass%3D%2A",  // Overlong UTF-8 encoded )(
                "https://app.org/directory?dn=cn%3Dadmin%2Cdc%3Ddomain",          // URL encoded DN
                "http://web.com/search?attr=user%20%29%28%26%28mail%3D%2A",       // URL encoded space and )(
                "https://domain.org/filter?name=admin%0A%29%28objectClass%3D%2A"  // URL encoded newline
        };

        for (String edgeCase : edgeCases) {
            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(edgeCase),
                    "Edge case LDAP injection should be detected: " + sanitizeForDisplay(edgeCase));

            assertNotNull(exception.getFailureType(),
                    "Edge case should have proper failure type classification");
        }
    }

    @Test
    @DisplayName("Should validate authentication bypass LDAP attacks are blocked")
    void shouldValidateAuthenticationBypassBlocking() {
        String[] authBypassAttacks = {
                "http://example.com/login?username=*)(uid=*))(|(uid=*",
                "https://site.org/auth?user=admin)(&(password=*)",
                "http://app.com/directory?login=*)|(objectClass=*",
                "https://secure.com/ldap?name=*))%00(&(objectClass=user",
                "http://domain.com/auth?user=admin))(|(cn=*",
                "https://test.org/login?param=user*)(|(uid=*",
                "http://site.com/directory?filter=*)(userPassword=*)",
                "https://app.org/auth?query=admin)(&(objectClass=*)(cn=*",
                "http://web.com/login?username=user)|(memberOf=*",
                "https://domain.org/auth?name=*)(|(objectClass=person)(uid=*"
        };

        for (String attack : authBypassAttacks) {
            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Authentication bypass LDAP attack should be blocked: " + sanitizeForDisplay(attack));

            assertTrue(
                    exception.getFailureType() == UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED ||
                            exception.getFailureType() == UrlSecurityFailureType.INVALID_CHARACTER ||
                            exception.getFailureType() == UrlSecurityFailureType.MALFORMED_INPUT,
                    "Authentication bypass should be properly classified as dangerous"
            );
        }
    }

    @Test
    @DisplayName("Should handle LDAP wildcard and enumeration attacks")
    void shouldHandleLdapWildcardEnumerationAttacks() {
        String[] wildcardAttacks = {
                "http://example.com/search?query=a*",
                "https://site.org/directory?name=*admin*",
                "http://app.com/users?filter=user*",
                "https://secure.com/ldap?search=*",
                "http://domain.com/auth?username=t*st",
                "https://test.org/directory?email=*@domain.com",
                "http://site.com/search?attr=admin*)(objectClass=*",
                "https://app.org/ldap?query=*)(|(uid=*",
                "http://web.com/users?name=a*)(&(objectClass=person)(uid=a*",
                "https://domain.org/directory?filter=user*)(&(cn=user*"
        };

        for (String attack : wildcardAttacks) {
            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "LDAP wildcard/enumeration attack should be detected: " + sanitizeForDisplay(attack));

            assertNotNull(exception.getFailureType(),
                    "Wildcard attack should be properly classified");
        }
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

    @Test
    @DisplayName("Should maintain consistent detection across similar LDAP patterns")
    void shouldConsistentlyDetectSimilarLdapPatterns() {
        String[] similarPatterns = {
                "http://example.com/auth?user=admin)(&(objectClass=*",
                "http://example.com/auth?user=admin)|(uid=*",
                "http://example.com/auth?user=admin)(&(cn=*",
                "http://example.com/auth?user=admin)|(objectClass=*",
                "http://example.com/auth?user=admin)(&(mail=*"
        };

        int detectionCount = 0;
        for (String pattern : similarPatterns) {
            try {
                pipeline.validate(pattern);
            } catch (UrlSecurityException e) {
                detectionCount++;
                assertTrue(
                        e.getFailureType() == UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED ||
                                e.getFailureType() == UrlSecurityFailureType.INVALID_CHARACTER ||
                                e.getFailureType() == UrlSecurityFailureType.MALFORMED_INPUT,
                        "Similar pattern should have consistent detection: " + pattern
                );
            }
        }

        assertEquals(similarPatterns.length, detectionCount,
                "All similar LDAP injection patterns should be consistently detected");
    }

    @Test
    @DisplayName("Should detect nested and complex LDAP filter injections")
    void shouldDetectComplexLdapFilterInjections() {
        String[] complexAttacks = {
                "http://example.com/search?filter=admin)(&(objectClass=*)(&(uid=*",
                "https://site.org/ldap?query=user)(&(cn=*)(&(mail=*",
                "http://app.com/directory?param=test)(&(sn=*)(&(givenName=*",
                "https://secure.com/auth?filter=admin)(|(objectClass=*)(&(uid=*",
                "http://domain.com/ldap?search=user)(|(cn=*)(&(mail=*",
                "https://test.org/directory?query=test)(&(objectClass=*)(|(uid=*",
                "http://site.com/search?param=admin)(&(|(cn=*)(sn=*)",
                "https://app.org/ldap?filter=user)(&(objectClass=person)(|(uid=*)(cn=*"
        };

        for (String attack : complexAttacks) {
            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Complex LDAP filter injection should be detected: " + sanitizeForDisplay(attack));

            assertTrue(
                    exception.getFailureType() == UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED ||
                            exception.getFailureType() == UrlSecurityFailureType.INVALID_CHARACTER ||
                            exception.getFailureType() == UrlSecurityFailureType.MALFORMED_INPUT,
                    "Complex filter injection should be properly classified"
            );
        }
    }

    @Test
    @DisplayName("Should handle LDAP DN manipulation and traversal attacks")
    void shouldHandleLdapDnManipulationAttacks() {
        String[] dnAttacks = {
                "http://example.com/directory?dn=cn=admin,dc=domain,dc=com)(&(objectClass=*",
                "https://site.org/ldap?base=uid=user,ou=people,dc=test)|(cn=*",
                "http://app.com/search?dn=cn=test)(&(ou=*",
                "https://secure.com/directory?base=../cn=admin,dc=domain,dc=com",
                "http://domain.com/ldap?dn=../../ou=people,dc=test,dc=com",
                "https://test.org/search?base=../../../dc=com",
                "http://site.com/directory?dn=..\\cn=root,dc=admin",
                "https://app.org/ldap?base=../ou=system,dc=directory"
        };

        for (String attack : dnAttacks) {
            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "LDAP DN manipulation attack should be detected: " + sanitizeForDisplay(attack));

            assertNotNull(exception.getFailureType(),
                    "DN manipulation attack should be properly classified");
        }
    }

    private String sanitizeForDisplay(String input) {
        if (input == null) return "null";
        return input.length() > 100 ?
                input.substring(0, 100) + "..." : input;
    }
}