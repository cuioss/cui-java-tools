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

import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.generator.junit.parameterized.TypeGeneratorSource;
import de.cuioss.http.security.config.SecurityConfiguration;
import de.cuioss.http.security.core.UrlSecurityFailureType;
import de.cuioss.http.security.exceptions.UrlSecurityException;
import de.cuioss.http.security.generators.header.HttpHeaderInjectionAttackGenerator;
import de.cuioss.http.security.monitoring.SecurityEventCounter;
import de.cuioss.http.security.pipeline.URLPathValidationPipeline;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * T15: Test HTTP header injection patterns
 *
 * <p>
 * This test class implements Task T15 from the HTTP security validation plan,
 * focusing on testing HTTP header injection attacks that attempt to manipulate
 * HTTP headers through web application inputs. HTTP header injection represents
 * a critical vulnerability that can lead to response splitting, cache poisoning,
 * cross-site scripting, session hijacking, and other security issues.
 * </p>
 *
 * <h3>Test Coverage</h3>
 * <ul>
 *   <li>CRLF Injection - Carriage Return Line Feed character injection</li>
 *   <li>HTTP Response Splitting - Complete HTTP response manipulation</li>
 *   <li>Header Injection via URL Parameters - Parameter-based header injection</li>
 *   <li>Cookie Injection Attacks - Malicious cookie header manipulation</li>
 *   <li>Location Header Injection - Redirect header manipulation</li>
 *   <li>Content-Type Header Injection - MIME type manipulation attacks</li>
 *   <li>Cache Poisoning Attacks - Cache-Control header manipulation</li>
 *   <li>Session Hijacking Headers - Session-related header injection</li>
 *   <li>XSS via Header Injection - Script injection through headers</li>
 *   <li>Authentication Header Bypass - Authorization header manipulation</li>
 *   <li>CORS Header Manipulation - Cross-origin header injection attacks</li>
 *   <li>Security Header Bypass - Security policy header manipulation</li>
 *   <li>Custom Header Injection - Application-specific header attacks</li>
 *   <li>Multi-line Header Injection - Complex multi-header attacks</li>
 *   <li>Encoded Header Injection - URL/Base64 encoded header attacks</li>
 * </ul>
 *
 * <h3>Security Standards Compliance</h3>
 * <p>
 * This test ensures compliance with:
 * </p>
 * <ul>
 *   <li>OWASP Top 10: A03:2021 – Injection</li>
 *   <li>CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers</li>
 *   <li>CWE-116: Improper Encoding or Escaping of Output</li>
 *   <li>RFC 7230: Hypertext Transfer Protocol (HTTP/1.1): Message Syntax</li>
 *   <li>NIST SP 800-53: SI-10 Information Input Validation</li>
 * </ul>
 *
 * <h3>Performance Requirements</h3>
 * <p>
 * Each validation must complete within 8ms to ensure production feasibility.
 * HTTP header injection detection should not introduce significant latency to
 * web application response processing.
 * </p>
 *
 * @see HttpHeaderInjectionAttackGenerator
 * @see URLPathValidationPipeline
 * @author Generated for HTTP Security Validation (T15)
 * @version 1.0.0
 */
@EnableGeneratorController
@DisplayName("T15: HTTP Header Injection Attack Validation Tests")
class HttpHeaderInjectionAttackTest {

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
    @TypeGeneratorSource(value = HttpHeaderInjectionAttackGenerator.class, count = 150)
    @DisplayName("All HTTP header injection attacks should be rejected")
    void shouldRejectAllHttpHeaderInjectionAttacks(String headerAttackPattern) {
        var exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(headerAttackPattern),
                "HTTP header injection attack should be rejected: " + sanitizeForDisplay(headerAttackPattern));

        assertTrue(
                exception.getFailureType() == UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED ||
                        exception.getFailureType() == UrlSecurityFailureType.INVALID_CHARACTER ||
                        exception.getFailureType() == UrlSecurityFailureType.CONTROL_CHARACTERS ||
                        exception.getFailureType() == UrlSecurityFailureType.MALFORMED_INPUT,
                "HTTP header injection should be detected with appropriate failure type, got: " + exception.getFailureType()
        );

        assertTrue(eventCounter.getCount(UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED) +
                eventCounter.getCount(UrlSecurityFailureType.INVALID_CHARACTER) +
                eventCounter.getCount(UrlSecurityFailureType.CONTROL_CHARACTERS) +
                eventCounter.getCount(UrlSecurityFailureType.MALFORMED_INPUT) > 0,
                "Security event counter should track HTTP header injection detection");
    }

    @Test
    @DisplayName("Known dangerous HTTP header injection patterns should be rejected")
    void shouldRejectKnownHttpHeaderInjectionAttacks() {
        String[] knownAttacks = {
                "http://example.com/redirect?url=normal%0d%0aX-Injected: malicious",
                "https://site.org/login?redirect=test\r\nLocation: http://evil.com",
                "http://app.com/header?value=data\nSet-Cookie: admin=true",
                "https://api.com/response?param=input%0AContent-Type: text/html",
                "http://test.com/cookie?name=user%0d%0aSet-Cookie: role=administrator",
                "https://secure.com/redirect?url=safe.com%0d%0aLocation: http://evil.com",
                "http://domain.com/page?content=test%0d%0a%0d%0a<html><script>alert('XSS')</script></html>",
                "https://web.org/login?user=admin%0d%0aAuthorization: Bearer hijacked-token",
                "http://site.com/api?origin=normal%0d%0aAccess-Control-Allow-Origin: *",
                "https://app.org/header?security=test%0d%0aX-XSS-Protection: 0",
                "http://example.org/multi?param=test%0d%0aX-First: value1%0d%0aX-Second: value2",
                "https://test.com/encoded?value=test%250d%250aX-Injected: value",
                "http://app.com/cache?param=normal%0d%0aCache-Control: public, max-age=31536000",
                "https://site.org/session?user=test%0d%0aSet-Cookie: JSESSIONID=hijacked",
                "http://domain.com/cors?data=input%0d%0aAccess-Control-Allow-Credentials: true"
        };

        for (String attack : knownAttacks) {
            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Known HTTP header injection attack should be rejected: " + sanitizeForDisplay(attack));

            assertTrue(
                    exception.getFailureType() == UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED ||
                            exception.getFailureType() == UrlSecurityFailureType.INVALID_CHARACTER ||
                            exception.getFailureType() == UrlSecurityFailureType.CONTROL_CHARACTERS ||
                            exception.getFailureType() == UrlSecurityFailureType.MALFORMED_INPUT,
                    "HTTP header injection should be properly categorized for: " + sanitizeForDisplay(attack)
            );
        }
    }

    @Test
    @DisplayName("HTTP header injection detection should handle CRLF edge cases")
    void shouldHandleCrlfEdgeCasesInHttpHeaderInjection() {
        String[] crlfEdgeCases = {
                "http://example.com/test?param=normal%0D%0AX-Injected: malicious",    // Uppercase hex
                "https://site.org/page?value=test%0d%0a%20X-Header: injected",        // Space after CRLF
                "http://app.com/api?data=input%0d%0a%09X-Tab: header",                // Tab after CRLF
            "https://secure.com/redirect?url=test%0d%20%0aX-Space: value",        // Space in CRLF
                "http://domain.com/header?param=data%0a%0dX-Reversed: crlf",          // Reversed CRLF
                "https://test.org/login?user=admin%0d%0aLocation: http://evil.com",   // URL encoded CRLF
                "http://site.com/cookie?name=test%0d%0aSet-Cookie: admin=true", // Standard CRLF
                "https://app.org/page?content=input%c0%aaX-Overlong: utf8",           // Overlong UTF-8
                "http://web.com/api?param=test%e5%98%8a%e5%98%8dX-Unicode: header",   // Unicode variants
                "https://domain.org/header?value=data%85X-NEL: nextline"           // Unicode NEL encoded
        };

        for (String edgeCase : crlfEdgeCases) {
            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(edgeCase),
                    "CRLF edge case should be detected: " + sanitizeForDisplay(edgeCase));

            assertNotNull(exception.getFailureType(),
                    "Edge case should have proper failure type classification");
        }
    }

    @Test
    @DisplayName("Should validate HTTP response splitting attacks are blocked")
    void shouldValidateHttpResponseSplittingBlocking() {
        String[] responseSplittingAttacks = {
                "http://example.com/page?param=test%0d%0a%0d%0a<html><body><h1>Hacked</h1></body></html>",
                "https://site.org/redirect?url=normal\r\n\r\n<script>document.location='http://evil.com'</script>",
                "http://app.com/response?data=value%0d%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 200 OK",
                "https://secure.com/api?param=input\n\nHTTP/1.1 302 Found\nLocation: javascript:alert('XSS')",
                "http://domain.com/page?content=data%0d%0a%0d%0a<html><script>document.cookie='admin=true'</script>",
                "https://test.org/header?value=input\\r\\n\\r\\n<iframe src='http://attacker.com'></iframe>",
                "http://site.com/cookie?name=test%0d%0aSet-Cookie: session=hijacked%0d%0a%0d%0a<html>Controlled</html>",
                "https://app.org/response?param=normal%0d%0a%0d%0aHTTP/1.1 301 Moved%0d%0aLocation: http://evil.com"
        };

        for (String attack : responseSplittingAttacks) {
            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "HTTP response splitting attack should be blocked: " + sanitizeForDisplay(attack));

            assertTrue(
                    exception.getFailureType() == UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED ||
                            exception.getFailureType() == UrlSecurityFailureType.INVALID_CHARACTER ||
                            exception.getFailureType() == UrlSecurityFailureType.CONTROL_CHARACTERS ||
                            exception.getFailureType() == UrlSecurityFailureType.MALFORMED_INPUT,
                    "Response splitting should be properly classified as dangerous"
            );
        }
    }

    @Test
    @DisplayName("Should handle cookie and session header injection attacks")
    void shouldHandleCookieSessionHeaderInjectionAttacks() {
        String[] cookieSessionAttacks = {
                "http://example.com/login?name=normal%0d%0aSet-Cookie: admin=true; Path=/",
                "https://site.org/auth?user=test\r\nSet-Cookie: session=ABC123; HttpOnly; Secure",
                "http://app.com/cookie?value=data\nSet-Cookie: role=administrator",
                "https://secure.com/session?param=input%0ASet-Cookie: auth=bypassed; Domain=.evil.com",
                "http://domain.com/login?user=admin%0d%0aSet-Cookie: JSESSIONID=hijacked",
                "https://test.org/auth?session=test\r\nSet-Cookie: PHPSESSID=attacker-controlled",
                "http://site.com/cookie?name=user%0d%0aSet-Cookie: csrf_token=disabled",
                "https://app.org/session?value=normal\nSet-Cookie: login_state=authenticated"
        };

        for (String attack : cookieSessionAttacks) {
            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Cookie/session header injection should be detected: " + sanitizeForDisplay(attack));

            assertNotNull(exception.getFailureType(),
                    "Cookie attack should be properly classified");
        }
    }

    @Test
    @DisplayName("Should properly track HTTP header injection security events")
    void shouldTrackHttpHeaderInjectionEvents() {
        long initialCount = eventCounter.getCount(UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED) +
                eventCounter.getCount(UrlSecurityFailureType.INVALID_CHARACTER) +
                eventCounter.getCount(UrlSecurityFailureType.CONTROL_CHARACTERS) +
                eventCounter.getCount(UrlSecurityFailureType.MALFORMED_INPUT);

        String testAttack = "http://example.com/test?param=normal%0d%0aX-Injected: malicious";

        assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(testAttack));

        long finalCount = eventCounter.getCount(UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED) +
                eventCounter.getCount(UrlSecurityFailureType.INVALID_CHARACTER) +
                eventCounter.getCount(UrlSecurityFailureType.CONTROL_CHARACTERS) +
                eventCounter.getCount(UrlSecurityFailureType.MALFORMED_INPUT);

        assertTrue(finalCount > initialCount,
                "HTTP header injection detection should increment security event counter");
    }

    @Test
    @DisplayName("Should maintain consistent detection across similar header patterns")
    void shouldConsistentlyDetectSimilarHeaderPatterns() {
        String[] similarPatterns = {
                "http://example.com/test?param=data%0d%0aX-Injected: header",
                "http://example.com/test?param=data\r\nX-Injected: header",
                "http://example.com/test?param=data\nX-Injected: header",
                "http://example.com/test?param=data%0AX-Injected: header",
                "http://example.com/test?param=data\\r\\nX-Injected: header"
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
                                e.getFailureType() == UrlSecurityFailureType.CONTROL_CHARACTERS ||
                                e.getFailureType() == UrlSecurityFailureType.MALFORMED_INPUT,
                        "Similar pattern should have consistent detection: " + pattern
                );
            }
        }

        assertEquals(similarPatterns.length, detectionCount,
                "All similar HTTP header injection patterns should be consistently detected");
    }

    @Test
    @DisplayName("Should detect security and CORS header manipulation attacks")
    void shouldDetectSecurityCorsHeaderManipulation() {
        String[] securityCorsAttacks = {
                "http://example.com/api?param=test%0d%0aStrict-Transport-Security: max-age=0",
                "https://site.org/cors?origin=normal\r\nAccess-Control-Allow-Origin: *",
                "http://app.com/security?value=data\nX-Content-Type-Options: ",
                "https://secure.com/header?param=input%0AX-Frame-Options: ALLOWALL",
                "http://domain.com/csp?content=test%0d%0aContent-Security-Policy: default-src *",
                "https://test.org/xss?param=data\r\nX-XSS-Protection: 0",
                "http://site.com/cors?origin=input%0d%0aAccess-Control-Allow-Credentials: true",
                "https://app.org/security?value=normal\nReferrer-Policy: no-referrer-when-downgrade"
        };

        for (String attack : securityCorsAttacks) {
            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Security/CORS header manipulation should be detected: " + sanitizeForDisplay(attack));

            assertTrue(
                    exception.getFailureType() == UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED ||
                            exception.getFailureType() == UrlSecurityFailureType.INVALID_CHARACTER ||
                            exception.getFailureType() == UrlSecurityFailureType.CONTROL_CHARACTERS ||
                            exception.getFailureType() == UrlSecurityFailureType.MALFORMED_INPUT,
                    "Security header manipulation should be properly classified"
            );
        }
    }

    @Test
    @DisplayName("Should handle multi-line and complex header injection attacks")
    void shouldHandleMultiLineComplexHeaderInjections() {
        String[] complexAttacks = {
                "http://example.com/multi?param=test%0d%0aX-First: value1%0d%0aX-Second: value2%0d%0aX-Third: value3",
                "https://site.org/complex?data=normal\r\nLocation: http://evil.com\r\nSet-Cookie: admin=true\r\nX-Injected: success",
                "http://app.com/headers?value=input\nContent-Type: text/html\nCache-Control: no-cache\nX-Custom: injected",
                "https://secure.com/multi?param=data%0ASet-Cookie: session=hijacked%0ALocation: javascript:alert('XSS')",
                "http://domain.com/complex?input=test%0d%0aAuthorization: Bearer token%0d%0aX-Role: admin",
                "https://test.org/headers?value=normal%0d%0aX-Frame-Options: DENY%0d%0aContent-Security-Policy: none",
                "http://site.com/cors?param=multi%0d%0aAccess-Control-Allow-Origin: *%0d%0aAccess-Control-Allow-Credentials: true",
                "https://app.org/injection?data=complex%0d%0aCache-Control: no-store%0d%0aExpires: Thu, 01 Jan 1970 00:00:00 GMT"
        };

        for (String attack : complexAttacks) {
            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Complex multi-line header injection should be detected: " + sanitizeForDisplay(attack));

            assertNotNull(exception.getFailureType(),
                    "Complex attack should be properly classified");
        }
    }

    private String sanitizeForDisplay(String input) {
        if (input == null) return "null";
        return input.length() > 100 ?
                input.substring(0, 100) + "..." : input;
    }
}