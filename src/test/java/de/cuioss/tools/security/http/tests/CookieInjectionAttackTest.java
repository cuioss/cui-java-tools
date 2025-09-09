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
import de.cuioss.tools.security.http.generators.CookieInjectionAttackGenerator;
import de.cuioss.tools.security.http.monitoring.SecurityEventCounter;
import de.cuioss.tools.security.http.pipeline.URLPathValidationPipeline;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * T17: Test cookie injection attacks
 *
 * <p>
 * This test class implements Task T17 from the HTTP security validation plan,
 * focusing on testing cookie injection attacks that attempt to manipulate
 * HTTP cookie headers to bypass security controls, inject malicious content,
 * or perform session manipulation attacks using specialized generators and
 * comprehensive attack vectors.
 * </p>
 *
 * <h3>Test Coverage</h3>
 * <ul>
 *   <li>CRLF injection in cookie values and parameters</li>
 *   <li>Cookie header injection and manipulation</li>
 *   <li>Session fixation and hijacking attacks</li>
 *   <li>Authentication bypass through cookie manipulation</li>
 *   <li>Cross-site cookie injection attacks</li>
 *   <li>Path traversal attempts via cookie parameters</li>
 *   <li>XSS injection through cookie values</li>
 *   <li>SQL injection via cookie parameters</li>
 *   <li>Command injection through cookie values</li>
 *   <li>Cookie overflow and buffer manipulation</li>
 *   <li>Cookie attribute manipulation (Secure, HttpOnly, SameSite)</li>
 *   <li>Cookie parsing confusion attacks</li>
 *   <li>Unicode-based cookie manipulation</li>
 *   <li>Cookie smuggling attacks</li>
 *   <li>Domain and path manipulation in cookies</li>
 * </ul>
 *
 * <h3>Security Standards</h3>
 * <ul>
 *   <li>RFC 6265 - HTTP State Management Mechanism (Cookies)</li>
 *   <li>OWASP - Session Management Cheat Sheet</li>
 *   <li>OWASP Top 10 - Broken Authentication and Session Management</li>
 *   <li>CWE-113 - Improper Neutralization of CRLF Sequences in HTTP Headers</li>
 *   <li>CWE-384 - Session Fixation</li>
 *   <li>CWE-472 - External Control of Assumed-Immutable Web Parameter</li>
 *   <li>CWE-79 - Cross-site Scripting (XSS)</li>
 *   <li>CWE-89 - SQL Injection</li>
 *   <li>CWE-78 - OS Command Injection</li>
 * </ul>
 *
 * Implements: Task T17 from HTTP verification specification
 *
 * @author Claude Code Generator
 * @since 2.5
 */
@EnableGeneratorController
@DisplayName("T17: Cookie Injection Attack Tests")
class CookieInjectionAttackTest {

    private URLPathValidationPipeline pipeline;
    private SecurityEventCounter eventCounter;
    private SecurityConfiguration config;

    @BeforeEach
    void setUp() {
        config = SecurityConfiguration.defaults();
        eventCounter = new SecurityEventCounter();
        pipeline = new URLPathValidationPipeline(config, eventCounter);
    }

    /**
     * Test comprehensive cookie injection attack patterns.
     *
     * <p>
     * Uses CookieInjectionAttackGenerator which provides 15 different types
     * of cookie injection attacks including CRLF injection, session fixation,
     * authentication bypass, XSS, SQL injection, and other cookie manipulation
     * techniques.
     * </p>
     *
     * @param cookieAttackPattern A cookie injection attack pattern
     */
    @ParameterizedTest
    @TypeGeneratorSource(value = CookieInjectionAttackGenerator.class, count = 180)
    @DisplayName("All cookie injection attacks should be rejected")
    void shouldRejectAllCookieInjectionAttacks(String cookieAttackPattern) {
        // Given: A cookie injection attack pattern from the generator
        long initialEventCount = eventCounter.getTotalCount();

        // When: Attempting to validate the cookie injection attack
        var exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(cookieAttackPattern),
                "Cookie injection attack should be rejected: " + cookieAttackPattern);

        // Then: The validation should fail with appropriate security event
        assertNotNull(exception, "Exception should be thrown for cookie injection attack");
        assertTrue(isCookieInjectionRelatedFailure(exception.getFailureType()),
                "Failure type should be cookie injection related: " + exception.getFailureType() +
                        " for pattern: " + cookieAttackPattern);

        // And: Original malicious input should be preserved
        assertEquals(cookieAttackPattern, exception.getOriginalInput(),
                "Original input should be preserved in exception");

        // And: Security event should be recorded
        assertTrue(eventCounter.getTotalCount() > initialEventCount,
                "Security event should be recorded for: " + cookieAttackPattern);
    }

    /**
     * Test specific CRLF injection attacks in cookie parameters.
     *
     * <p>
     * Tests attacks that inject CRLF sequences (\r\n) into cookie parameters
     * to manipulate HTTP headers and perform header injection attacks.
     * </p>
     */
    @Test
    @DisplayName("CRLF injection in cookie parameters must be blocked")
    void shouldBlockCrlfCookieInjection() {
        String[] crlfCookieAttacks = {
                // Basic CRLF injection with Set-Cookie
                "/login?cookie=value%0d%0aSet-Cookie: admin=true",
                "/authenticate?session=abc123%0d%0aSet-Cookie: role=administrator",
                "/profile?auth=token%0a%0aSet-Cookie: authenticated=yes",

                // CRLF with privilege escalation
                "/admin?user=guest%0d%0aSet-Cookie: privilege=root%0d%0a",
                "/secure?data=test%0d%0aSet-Cookie: session=hijacked; HttpOnly=false",

                // CRLF with multiple header injection
                "/api/auth?param=val%0d%0aSet-Cookie: security=disabled%0d%0aLocation: /admin",
                "/dashboard?id=123%0a%0aSet-Cookie: access_level=admin",
                "/account?token=xyz%0d%0aSet-Cookie: bypass=true%0d%0aContent-Type: text/html"
        };

        for (String attack : crlfCookieAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "CRLF cookie injection should be rejected: " + attack);

            assertNotNull(exception);
            assertTrue(isCookieInjectionRelatedFailure(exception.getFailureType()),
                    "Should detect CRLF cookie injection: " + exception.getFailureType());
            assertTrue(eventCounter.getTotalCount() > initialEventCount,
                    "Security event should be recorded for CRLF cookie injection");
        }
    }

    /**
     * Test cookie header injection attacks.
     *
     * <p>
     * Tests attacks that attempt to inject additional Cookie headers
     * to manipulate authentication and session state.
     * </p>
     */
    @Test
    @DisplayName("Cookie header injection attacks must be blocked")
    void shouldBlockCookieHeaderInjection() {
        String[] headerInjectionAttacks = {
                // Basic cookie header injection
                "/login?cookie=normal%0d%0aCookie: admin=true",
                "/session?session=user123%0d%0aCookie: role=administrator; secure",
                "/auth?auth=basic%0a%0aCookie: privilege=root",

                // Cookie injection with authorization bypass
                "/secure?data=payload%0d%0aCookie: authenticated=yes%0d%0aAuthorization: Bearer admin",
                "/admin?user=test%0d%0aCookie: access_token=hijacked_token",

                // Cookie injection with additional malicious headers
                "/api?login=attempt%0d%0aCookie: session_id=admin_session%0d%0aX-Admin: true",
                "/validate?user=guest%0a%0aCookie: security_level=maximum",
                "/check?auth=user%0d%0aCookie: bypass_csrf=true%0d%0aContent-Length: 0"
        };

        for (String attack : headerInjectionAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Cookie header injection should be rejected: " + attack);

            assertNotNull(exception);
            assertTrue(isCookieInjectionRelatedFailure(exception.getFailureType()),
                    "Should detect cookie header injection: " + exception.getFailureType());
            assertTrue(eventCounter.getTotalCount() > initialEventCount,
                    "Security event should be recorded for cookie header injection");
        }
    }

    /**
     * Test session fixation attack patterns.
     *
     * <p>
     * Tests attacks that attempt to fix session identifiers to known values
     * to facilitate session hijacking.
     * </p>
     */
    @Test
    @DisplayName("Session fixation attacks must be blocked")
    void shouldBlockSessionFixationAttacks() {
        String[] sessionFixationAttacks = {
                // Common session fixation patterns
                "/login?JSESSIONID=ATTACKER_SESSION_12345",
                "/authenticate?sessionid=fixed_session_token_999",
                "/secure?PHPSESSID=malicious_session_abc123",
                "/profile?session_token=predetermined_token_xyz",

                // Framework-specific session fixation
                "/admin?auth_session=attacker_controlled_session",
                "/api/auth?user_session=fixed_by_attacker_789",
                "/dashboard?login_session=known_session_identifier",
                "/account?secure_session=predictable_session_456"
        };

        for (String attack : sessionFixationAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Session fixation attack should be rejected: " + attack);

            assertNotNull(exception);
            assertTrue(isCookieInjectionRelatedFailure(exception.getFailureType()),
                    "Should detect session fixation: " + exception.getFailureType());
            assertTrue(eventCounter.getTotalCount() > initialEventCount,
                    "Security event should be recorded for session fixation");
        }
    }

    /**
     * Test authentication bypass cookie attacks.
     *
     * <p>
     * Tests attacks that attempt to bypass authentication by manipulating
     * authentication-related cookie values.
     * </p>
     */
    @Test
    @DisplayName("Authentication bypass cookie attacks must be blocked")
    void shouldBlockAuthenticationBypassCookies() {
        String[] authBypassAttacks = {
                // Authentication state manipulation
                "/secure?auth=false%0d%0aSet-Cookie: authenticated=true",
                "/admin?user=guest%0d%0aCookie: role=admin",
                "/api/protected?login=fail%0d%0aSet-Cookie: access_level=root%0d%0a",

                // Permission escalation via cookies
                "/profile?check=denied%0d%0aCookie: permission=granted; secure=false",
                "/dashboard?validate=user%0a%0aSet-Cookie: admin=true",
                "/settings?security=low%0d%0aCookie: privilege=maximum%0d%0aHttpOnly=false",

                // Access control bypass
                "/protected?access=restricted%0d%0aSet-Cookie: bypass=enabled",
                "/secure/data?permission=denied%0d%0aCookie: override=true%0d%0aSameSite=None"
        };

        for (String attack : authBypassAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Authentication bypass attack should be rejected: " + attack);

            assertNotNull(exception);
            assertTrue(isCookieInjectionRelatedFailure(exception.getFailureType()),
                    "Should detect authentication bypass: " + exception.getFailureType());
            assertTrue(eventCounter.getTotalCount() > initialEventCount,
                    "Security event should be recorded for authentication bypass");
        }
    }

    /**
     * Test cross-site cookie injection attacks.
     *
     * <p>
     * Tests attacks that attempt to set cookies for different domains
     * to perform cross-site attacks.
     * </p>
     */
    @Test
    @DisplayName("Cross-site cookie injection attacks must be blocked")
    void shouldBlockCrossSiteCookieInjection() {
        String[] crossSiteAttacks = {
                // Cross-domain cookie setting
                "/api/data?data=test%0d%0aSet-Cookie: session=hijacked; domain=evil.com",
                "/secure?cookie=value%0d%0aSet-Cookie: auth=admin; domain=.attacker.com",
                "/profile?user=victim%0a%0aSet-Cookie: token=stolen; domain=malicious.org",

                // Subdomain manipulation
                "/login?login=attempt%0d%0aSet-Cookie: role=admin; domain=bad-site.net%0d%0a",
                "/auth?session=active%0d%0aCookie: privilege=root; domain=evil-domain.com",
                "/admin?auth=token%0d%0aSet-Cookie: access=granted; domain=.hacker.org",

                // Domain confusion attacks
                "/validate?validate=user%0a%0aSet-Cookie: admin=true; domain=attacker-site.com",
                "/secure/api?secure=false%0d%0aSet-Cookie: bypass=enabled; domain=.malicious.net%0d%0aPath: /"
        };

        for (String attack : crossSiteAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Cross-site cookie injection should be rejected: " + attack);

            assertNotNull(exception);
            assertTrue(isCookieInjectionRelatedFailure(exception.getFailureType()),
                    "Should detect cross-site cookie injection: " + exception.getFailureType());
            assertTrue(eventCounter.getTotalCount() > initialEventCount,
                    "Security event should be recorded for cross-site cookie injection");
        }
    }

    /**
     * Test XSS injection via cookie parameters.
     *
     * <p>
     * Tests attacks that attempt to inject JavaScript code through
     * cookie parameters for cross-site scripting attacks.
     * </p>
     */
    @Test
    @DisplayName("XSS injection via cookie parameters must be blocked")
    void shouldBlockXssCookieInjection() {
        String[] xssCookieAttacks = {
                // Basic XSS in cookie parameters
                "/profile?cookie=%3cscript%3ealert(1)%3c/script%3e",
                "/session?session=javascript:alert('XSS')",
                "/auth?auth=%22%3e%3cscript%3ealert(document.cookie)%3c/script%3e",

                // Image and SVG-based XSS
                "/secure?user=%3cimg%20src=x%20onerror=alert(1)%3e",
                "/api/data?data=%3csvg%20onload=alert('cookie')%3e%3c/svg%3e",

                // Advanced XSS techniques
                "/login?token=%27%3e%3cscript%3eeval(atob('YWxlcnQoMSk='))%3c/script%3e",
                "/admin?login=%3ciframe%20src=javascript:alert(1)%3e%3c/iframe%3e",
                "/validate?validate=%3cscript%20src=http://evil.com/xss.js%3e%3c/script%3e"
        };

        for (String attack : xssCookieAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "XSS cookie injection should be rejected: " + attack);

            assertNotNull(exception);
            assertTrue(isCookieInjectionRelatedFailure(exception.getFailureType()),
                    "Should detect XSS cookie injection: " + exception.getFailureType());
            assertTrue(eventCounter.getTotalCount() > initialEventCount,
                    "Security event should be recorded for XSS cookie injection");
        }
    }

    /**
     * Test SQL injection via cookie parameters.
     *
     * <p>
     * Tests attacks that attempt to inject SQL commands through
     * cookie parameters to manipulate database queries.
     * </p>
     */
    @Test
    @DisplayName("SQL injection via cookie parameters must be blocked")
    void shouldBlockSqlInjectionCookies() {
        String[] sqlInjectionAttacks = {
                // Classic SQL injection patterns
                "/profile?cookie='; DROP TABLE users; --",
                "/auth?session=admin' OR '1'='1",
                "/secure?auth=1' UNION SELECT password FROM admin_users --",

                // Data manipulation via SQL injection
                "/api/user?user='; INSERT INTO users VALUES ('hacker','password'); --",
                "/admin?data=' OR 1=1; UPDATE users SET role='admin' WHERE id=1; --",

                // Advanced SQL injection
                "/login?token=1'; EXEC xp_cmdshell('whoami'); --",
                "/validate?login=' UNION SELECT credit_card FROM payments --",
                "/secure/data?validate='; CREATE USER hacker IDENTIFIED BY 'password'; --"
        };

        for (String attack : sqlInjectionAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "SQL injection cookie attack should be rejected: " + attack);

            assertNotNull(exception);
            assertTrue(isCookieInjectionRelatedFailure(exception.getFailureType()),
                    "Should detect SQL injection cookie: " + exception.getFailureType());
            assertTrue(eventCounter.getTotalCount() > initialEventCount,
                    "Security event should be recorded for SQL injection cookie");
        }
    }

    /**
     * Test cookie overflow attacks.
     *
     * <p>
     * Tests attacks using extremely long cookie values that might
     * cause buffer overflows or memory exhaustion.
     * </p>
     */
    @Test
    @DisplayName("Cookie overflow attacks must be blocked")
    void shouldBlockCookieOverflowAttacks() {
        String longValue = "A".repeat(8192);
        String veryLongValue = "B".repeat(16384);

        String[] overflowAttacks = {
                // Large cookie values
                "/profile?cookie=" + longValue,
                "/session?session=" + veryLongValue,
                "/auth?auth=" + longValue.substring(0, 4000),

                // Large values with injection
                "/admin?user=" + longValue + "%0d%0aSet-Cookie: admin=true",
                "/secure?data=" + veryLongValue.substring(0, 2000) + "%0a%0aCookie: role=admin",

                // Overflow with parsing confusion
                "/api/data?token=" + longValue + "; role=admin",
                "/validate?login=" + veryLongValue.substring(0, 3000) + "%0d%0aX-Admin: true"
        };

        for (String attack : overflowAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Cookie overflow attack should be rejected: " + attack);

            assertNotNull(exception);
            assertTrue(eventCounter.getTotalCount() > initialEventCount,
                    "Security event should be recorded for cookie overflow");
        }
    }

    /**
     * Test cookie parsing confusion attacks.
     *
     * <p>
     * Tests attacks that exploit cookie parsing differences and
     * malformed cookie structures.
     * </p>
     */
    @Test
    @DisplayName("Cookie parsing confusion attacks must be blocked")
    void shouldBlockCookieParsingConfusion() {
        String[] parsingConfusionAttacks = {
                // Duplicate cookie names
                "/profile?cookie=val1; cookie=val2; admin=true",
                "/auth?session=\"quoted_value\"; role=admin",
                "/secure?auth=token;admin=true;user=guest",

                // Malformed cookie structures
                "/admin?data=test; ;admin=true; ;",
                "/api?user=name=value; role=admin",
                "/login?login=; admin=true;session=hijacked;",

                // Parsing confusion with special characters
                "/validate?token=abc;def;admin=true",
                "/secure/data?validate=user;=;admin=true;="
        };

        for (String attack : parsingConfusionAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Cookie parsing confusion should be rejected: " + attack);

            assertNotNull(exception);
            assertTrue(isCookieInjectionRelatedFailure(exception.getFailureType()),
                    "Should detect cookie parsing confusion: " + exception.getFailureType());
            assertTrue(eventCounter.getTotalCount() > initialEventCount,
                    "Security event should be recorded for cookie parsing confusion");
        }
    }

    /**
     * Test performance impact of cookie injection validation.
     *
     * <p>
     * Ensures that cookie injection detection doesn't significantly impact
     * validation performance, even with complex attack patterns.
     * </p>
     */
    @Test
    @DisplayName("Cookie injection validation should maintain performance")
    void shouldMaintainPerformanceWithCookieInjectionAttacks() {
        String complexCookiePattern = "/profile?cookie=value%0d%0aSet-Cookie: admin=true; domain=evil.com%0d%0aCookie: role=administrator%0d%0aSet-Cookie: session=hijacked; HttpOnly=false; Secure=false%0d%0aX-Admin: true%0d%0a%0d%0a";

        // Warm up
        for (int i = 0; i < 10; i++) {
            try {
                pipeline.validate(complexCookiePattern);
            } catch (UrlSecurityException ignored) {
            }
        }

        // Measure performance
        long startTime = System.nanoTime();
        for (int i = 0; i < 100; i++) {
            try {
                pipeline.validate(complexCookiePattern);
            } catch (UrlSecurityException ignored) {
            }
        }
        long endTime = System.nanoTime();

        long averageNanos = (endTime - startTime) / 100;
        long averageMillis = averageNanos / 1_000_000;

        // Should complete within reasonable time (< 8ms per validation)
        assertTrue(averageMillis < 8,
                "Cookie injection validation should complete within 8ms, actual: " + averageMillis + "ms");
    }

    /**
     * Test comprehensive edge cases in cookie injection detection.
     *
     * <p>
     * Tests various edge cases and corner conditions that might be
     * exploited in cookie injection attacks.
     * </p>
     */
    @Test
    @DisplayName("Cookie injection edge cases must be handled")
    void shouldHandleCookieInjectionEdgeCases() {
        String[] edgeCaseAttacks = {
                // Unicode cookie attacks
                "/profile?cookie=\u0061\u0064\u006d\u0069\u006e", // "admin" in Unicode
                "/auth?session=\u0000\u0061\u0064\u006d\u0069\u006e", // null byte + "admin"
                "/secure?auth=\u202e\u0061\u0064\u006d\u0069\u006e", // Right-to-left override

                // Cookie smuggling
                "/api?cookie=normal%0d%0a%0d%0aGET /admin HTTP/1.1%0d%0aCookie: admin=true",
                "/login?session=user%0a%0aGET /secure HTTP/1.1%0a%0aCookie: role=administrator",

                // Complex encoding combinations
                "/admin?data=test%25%30%64%25%30%61Set-Cookie:%20admin=true",
                "/validate?user=%2500%2500admin=true"
        };

        for (String attack : edgeCaseAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Cookie injection edge case should be rejected: " + attack);

            assertNotNull(exception);
            assertTrue(eventCounter.getTotalCount() > initialEventCount,
                    "Security event should be recorded for edge case");
        }
    }

    /**
     * Determines if a failure type is related to cookie injection attacks.
     *
     * @param failureType The failure type to check
     * @return true if the failure type indicates a cookie injection-related security issue
     */
    private boolean isCookieInjectionRelatedFailure(UrlSecurityFailureType failureType) {
        return failureType == UrlSecurityFailureType.CONTROL_CHARACTERS ||
                failureType == UrlSecurityFailureType.INVALID_CHARACTER ||
                failureType == UrlSecurityFailureType.MALFORMED_INPUT ||
                failureType == UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED ||
                failureType == UrlSecurityFailureType.INVALID_ENCODING ||
                failureType == UrlSecurityFailureType.PROTOCOL_VIOLATION ||
                failureType == UrlSecurityFailureType.RFC_VIOLATION ||
                failureType == UrlSecurityFailureType.XSS_DETECTED ||
                failureType == UrlSecurityFailureType.SQL_INJECTION_DETECTED ||
                failureType == UrlSecurityFailureType.COMMAND_INJECTION_DETECTED ||
                failureType == UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED ||
                failureType == UrlSecurityFailureType.INPUT_TOO_LONG ||
                failureType == UrlSecurityFailureType.NULL_BYTE_INJECTION ||
                failureType == UrlSecurityFailureType.UNICODE_NORMALIZATION_CHANGED;
    }
}