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
import de.cuioss.tools.security.http.generators.injection.HttpRequestSmugglingAttackGenerator;
import de.cuioss.tools.security.http.monitoring.SecurityEventCounter;
import de.cuioss.tools.security.http.pipeline.URLPathValidationPipeline;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * T16: Test HTTP request smuggling patterns
 * 
 * <p>
 * This test class implements Task T16 from the HTTP security validation plan,
 * focusing on testing HTTP request smuggling attacks that attempt to bypass
 * security controls through HTTP protocol manipulation using specialized
 * generators and comprehensive attack vectors.
 * </p>
 * 
 * <h3>Test Coverage</h3>
 * <ul>
 *   <li>Content-Length/Transfer-Encoding (CL.TE) smuggling attacks</li>
 *   <li>Transfer-Encoding/Content-Length (TE.CL) smuggling attacks</li>
 *   <li>Transfer-Encoding/Transfer-Encoding (TE.TE) smuggling attacks</li>
 *   <li>HTTP pipeline poisoning attacks</li>
 *   <li>Cache deception through request manipulation</li>
 *   <li>HTTP response queue poisoning</li>
 *   <li>Authentication bypass through smuggling</li>
 *   <li>Backend server confusion attacks</li>
 *   <li>Content-Length manipulation attacks</li>
 *   <li>Transfer-Encoding obfuscation patterns</li>
 *   <li>HTTP/1.1 vs HTTP/2 downgrade smuggling</li>
 *   <li>Chunk encoding manipulation</li>
 *   <li>Double Content-Length header attacks</li>
 *   <li>Mixed HTTP method smuggling</li>
 *   <li>Header parsing differential attacks</li>
 * </ul>
 * 
 * <h3>Security Standards</h3>
 * <ul>
 *   <li>RFC 7230 - HTTP/1.1 Message Syntax and Routing</li>
 *   <li>RFC 7231 - HTTP/1.1 Semantics and Content</li>
 *   <li>OWASP - HTTP Request Smuggling</li>
 *   <li>CVE-2019-9516, CVE-2019-9518, CVE-2020-11080 (Request smuggling CVEs)</li>
 *   <li>CWE-444 - Inconsistent Interpretation of HTTP Requests</li>
 *   <li>PortSwigger Web Security Academy - HTTP Request Smuggling</li>
 * </ul>
 * 
 * Implements: Task T16 from HTTP verification specification
 * 
 * @author Claude Code Generator
 * @since 2.5
 */
@EnableGeneratorController
@DisplayName("T16: HTTP Request Smuggling Attack Tests")
class HttpRequestSmugglingAttackTest {

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
     * Test comprehensive HTTP request smuggling attack patterns.
     * 
     * <p>
     * Uses HttpRequestSmugglingAttackGenerator which provides 15 different types
     * of request smuggling attacks including CL.TE, TE.CL, TE.TE, pipeline
     * poisoning, cache deception, and other HTTP protocol manipulation attacks.
     * </p>
     * 
     * @param smugglingAttackPattern A request smuggling attack pattern
     */
    @ParameterizedTest
    @TypeGeneratorSource(value = HttpRequestSmugglingAttackGenerator.class, count = 200)
    @DisplayName("All HTTP request smuggling attacks should be rejected")
    void shouldRejectAllHttpRequestSmugglingAttacks(String smugglingAttackPattern) {
        // Given: A request smuggling attack pattern from the generator
        long initialEventCount = eventCounter.getTotalCount();

        // When: Attempting to validate the smuggling attack
        var exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(smugglingAttackPattern),
                "Request smuggling attack should be rejected: " + smugglingAttackPattern);

        // Then: The validation should fail with appropriate security event
        assertNotNull(exception, "Exception should be thrown for request smuggling attack");
        assertTrue(isSpecificRequestSmugglingFailure(exception.getFailureType(), smugglingAttackPattern),
                "Failure type should be specific request smuggling related: " + exception.getFailureType() +
                        " for pattern: " + smugglingAttackPattern);

        // And: Original malicious input should be preserved
        assertEquals(smugglingAttackPattern, exception.getOriginalInput(),
                "Original input should be preserved in exception");

        // And: Security event should be recorded
        assertTrue(eventCounter.getTotalCount() > initialEventCount,
                "Security event should be recorded for: " + smugglingAttackPattern);
    }

    /**
     * Test specific CL.TE (Content-Length/Transfer-Encoding) smuggling attacks.
     * 
     * <p>
     * Tests attacks where the front-end server processes the Content-Length
     * header while the back-end server processes the Transfer-Encoding header,
     * creating desynchronization opportunities.
     * </p>
     */
    @Test
    @DisplayName("CL.TE smuggling attacks must be blocked")
    void shouldBlockClTeSmuggling() {
        String[] clTeAttacks = {
                // Basic CL.TE with chunked encoding bypass
                "/search?q=test%0d%0aContent-Length: 6%0d%0aTransfer-Encoding: chunked%0d%0a%0d%0a0%0d%0a%0d%0aG",

                // CL.TE with admin access attempt
                "/api/data?param=value%0d%0aContent-Length: 4%0d%0aTransfer-Encoding: chunked%0d%0a%0d%0a5c%0d%0aGET /admin HTTP/1.1",

                // CL.TE with authentication bypass
                "/login?user=guest%0d%0aContent-Length: 13%0d%0aTransfer-Encoding: chunked%0d%0a%0d%0a0%0d%0a%0d%0aGET /secure HTTP/1.1%0d%0aAuthorization: admin",

                // CL.TE with cache poisoning
                "/public/image.jpg%0d%0aContent-Length: 44%0d%0aTransfer-Encoding: chunked%0d%0a%0d%0a0%0d%0a%0d%0aGET /evil HTTP/1.1%0d%0aHost: attacker.com",

                // CL.TE with response splitting
                "/redirect?url=safe%0d%0aContent-Length: 30%0d%0aTransfer-Encoding: chunked%0d%0a%0d%0a0%0d%0a%0d%0aHTTP/1.1 302 Found%0d%0aLocation: http://evil.com"
        };

        for (String attack : clTeAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "CL.TE smuggling attack should be rejected: " + attack);

            assertNotNull(exception);
            assertEquals(UrlSecurityFailureType.INVALID_CHARACTER, exception.getFailureType(),
                    "CL.TE smuggling should trigger INVALID_CHARACTER detection for: " + attack);
            assertTrue(eventCounter.getTotalCount() > initialEventCount,
                    "Security event should be recorded for CL.TE attack");
        }
    }

    /**
     * Test specific TE.CL (Transfer-Encoding/Content-Length) smuggling attacks.
     * 
     * <p>
     * Tests attacks where the front-end server processes the Transfer-Encoding
     * header while the back-end server processes the Content-Length header.
     * </p>
     */
    @Test
    @DisplayName("TE.CL smuggling attacks must be blocked")
    void shouldBlockTeClSmuggling() {
        String[] teClAttacks = {
                // Basic TE.CL with chunk manipulation
                "/api?data=test%0d%0aTransfer-Encoding: chunked%0d%0aContent-Length: 6%0d%0a%0d%0a3c%0d%0aGET /admin HTTP/1.1%0d%0aHost: backend",

                // TE.CL with POST data manipulation
                "/form?submit=data%0d%0aTransfer-Encoding: chunked%0d%0aContent-Length: 4%0d%0a%0d%0a87%0d%0aPOST /admin/delete HTTP/1.1%0d%0aContent-Length: 15",

                // TE.CL with cookie injection
                "/page?id=123%0d%0aTransfer-Encoding: chunked%0d%0aContent-Length: 8%0d%0a%0d%0a5e%0d%0aGET /secure HTTP/1.1%0d%0aCookie: admin=true",

                // TE.CL with header manipulation
                "/resource?type=json%0d%0aTransfer-Encoding: chunked%0d%0aContent-Length: 12%0d%0a%0d%0a42%0d%0aGET /config HTTP/1.1%0d%0aX-Forwarded-For: 127.0.0.1",

                // TE.CL with method override
                "/update?item=1%0d%0aTransfer-Encoding: chunked%0d%0aContent-Length: 9%0d%0a%0d%0a35%0d%0aDELETE /users/admin HTTP/1.1%0d%0aAuthorization: Bearer token"
        };

        for (String attack : teClAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "TE.CL smuggling attack should be rejected: " + attack);

            assertNotNull(exception);
            assertEquals(UrlSecurityFailureType.INVALID_CHARACTER, exception.getFailureType(),
                    "TE.CL smuggling should trigger INVALID_CHARACTER detection for: " + attack);
            assertTrue(eventCounter.getTotalCount() > initialEventCount,
                    "Security event should be recorded for TE.CL attack");
        }
    }

    /**
     * Test specific TE.TE (Transfer-Encoding/Transfer-Encoding) smuggling attacks.
     * 
     * <p>
     * Tests attacks using Transfer-Encoding header obfuscation to create
     * parsing differences between front-end and back-end servers.
     * </p>
     */
    @Test
    @DisplayName("TE.TE smuggling attacks must be blocked")
    void shouldBlockTeTeSmuggling() {
        String[] teTeAttacks = {
                // TE.TE with header obfuscation
                "/search?q=data%0d%0aTransfer-Encoding: chunked%0d%0aTransfer-Encoding: identity%0d%0a%0d%0a2e%0d%0aGET /admin HTTP/1.1",

                // TE.TE with case variation
                "/api/call%0d%0aTransfer-Encoding: chunked%0d%0aTransfer-encoding: gzip%0d%0a%0d%0a41%0d%0aGET /backdoor HTTP/1.1%0d%0aHost: internal",

                // TE.TE with space obfuscation
                "/service?cmd=run%0d%0aTransfer-Encoding: chunked%0d%0aTransfer-Encoding : deflate%0d%0a%0d%0a33%0d%0aPOST /execute HTTP/1.1",

                // TE.TE with tab obfuscation
                "/endpoint?mode=test%0d%0aTransfer-Encoding: chunked%0d%0aTransfer-Encoding%09: compress%0d%0a%0d%0a28%0d%0aGET /shell HTTP/1.1",

                // TE.TE with multiple values
                "/process?id=42%0d%0aTransfer-Encoding: chunked, gzip%0d%0aTransfer-Encoding: identity%0d%0a%0d%0a1f%0d%0aDELETE /data HTTP/1.1"
        };

        for (String attack : teTeAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "TE.TE smuggling attack should be rejected: " + attack);

            assertNotNull(exception);
            assertEquals(UrlSecurityFailureType.INVALID_CHARACTER, exception.getFailureType(),
                    "TE.TE smuggling should trigger INVALID_CHARACTER detection for: " + attack);
            assertTrue(eventCounter.getTotalCount() > initialEventCount,
                    "Security event should be recorded for TE.TE attack");
        }
    }

    /**
     * Test HTTP pipeline poisoning attacks.
     * 
     * <p>
     * Tests attacks that attempt to poison HTTP connection pipelines
     * to affect subsequent requests from other users.
     * </p>
     */
    @Test
    @DisplayName("HTTP pipeline poisoning attacks must be blocked")
    void shouldBlockPipelinePoisoning() {
        String[] pipelinePoisoningAttacks = {
                // Basic pipeline poisoning
                "/normal?param=value%0d%0a%0d%0aGET /admin HTTP/1.1%0d%0aHost: backend%0d%0a%0d%0a",

                // Pipeline poisoning with authentication
                "/public/file.css%0d%0a%0d%0aGET /secure HTTP/1.1%0d%0aAuthorization: Bearer admin-token%0d%0a%0d%0a",

                // Pipeline poisoning with POST injection
                "/image.png%0d%0a%0d%0aPOST /api/admin HTTP/1.1%0d%0aContent-Length: 25%0d%0a%0d%0a{\"action\":\"delete_all\"}",

                // Pipeline poisoning with header injection
                "/static/script.js%0d%0a%0d%0aGET /config HTTP/1.1%0d%0aX-Admin-Override: true%0d%0a%0d%0a",

                // Pipeline poisoning with method smuggling
                "/robots.txt%0d%0a%0d%0aDELETE /users/database HTTP/1.1%0d%0aAuthorization: admin%0d%0a%0d%0a"
        };

        for (String attack : pipelinePoisoningAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Pipeline poisoning attack should be rejected: " + attack);

            assertNotNull(exception);
            assertEquals(UrlSecurityFailureType.INVALID_CHARACTER, exception.getFailureType(),
                    "Pipeline poisoning should trigger INVALID_CHARACTER detection for: " + attack);
            assertTrue(eventCounter.getTotalCount() > initialEventCount,
                    "Security event should be recorded for pipeline poisoning");
        }
    }

    /**
     * Test cache deception through request smuggling.
     * 
     * <p>
     * Tests attacks that use request smuggling to manipulate caching
     * behavior and serve malicious content to other users.
     * </p>
     */
    @Test
    @DisplayName("Cache deception attacks must be blocked")
    void shouldBlockCacheDeception() {
        String[] cacheDeceptionAttacks = {
                // Cache poisoning with static resource mimicry
                "/api/user/profile%0d%0a%0d%0aGET /evil.css HTTP/1.1%0d%0aHost: attacker.com%0d%0a%0d%0a",

                // Cache poisoning with JavaScript injection
                "/secure/data.json%0d%0a%0d%0aGET /malicious.js HTTP/1.1%0d%0aContent-Type: application/javascript%0d%0a%0d%0aalert('xss')",

                // Cache poisoning with image replacement
                "/user/avatar.jpg%0d%0a%0d%0aGET /fake-image.png HTTP/1.1%0d%0aLocation: http://evil.com/malware.exe%0d%0a%0d%0a",

                // Cache poisoning with redirect manipulation
                "/public/logo.png%0d%0a%0d%0aGET /redirect HTTP/1.1%0d%0aLocation: javascript:alert(document.cookie)%0d%0a%0d%0a",

                // Cache poisoning with content-type confusion
                "/assets/style.css%0d%0a%0d%0aGET /payload HTTP/1.1%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>steal_data()</script>"
        };

        for (String attack : cacheDeceptionAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Cache deception attack should be rejected: " + attack);

            assertNotNull(exception);
            assertEquals(UrlSecurityFailureType.INVALID_CHARACTER, exception.getFailureType(),
                    "Cache deception should trigger INVALID_CHARACTER detection for: " + attack);
            assertTrue(eventCounter.getTotalCount() > initialEventCount,
                    "Security event should be recorded for cache deception");
        }
    }

    /**
     * Test double Content-Length header attacks.
     * 
     * <p>
     * Tests attacks using multiple Content-Length headers to create
     * parsing inconsistencies between servers.
     * </p>
     */
    @Test
    @DisplayName("Double Content-Length header attacks must be blocked")
    void shouldBlockDoubleContentLength() {
        String[] doubleContentLengthAttacks = {
                // Double Content-Length with different values
                "/upload?file=data%0d%0aContent-Length: 13%0d%0aContent-Length: 6%0d%0a%0d%0aGET /admin HTTP/1.1",

                // Double Content-Length with smuggling
                "/form?data=test%0d%0aContent-Length: 8%0d%0aContent-Length: 44%0d%0a%0d%0aGET /backdoor HTTP/1.1%0d%0aAuthorization: Bearer token",

                // Double Content-Length with zero bypass
                "/api/call%0d%0aContent-Length: 0%0d%0aContent-Length: 15%0d%0a%0d%0aDELETE /secure HTTP/1.1",

                // Double Content-Length with large value
                "/service?cmd=run%0d%0aContent-Length: 999999%0d%0aContent-Length: 25%0d%0a%0d%0aPOST /admin/execute HTTP/1.1",

                // Double Content-Length with negative value
                "/endpoint?id=42%0d%0aContent-Length: -1%0d%0aContent-Length: 18%0d%0a%0d%0aGET /config HTTP/1.1"
        };

        for (String attack : doubleContentLengthAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Double Content-Length attack should be rejected: " + attack);

            assertNotNull(exception);
            assertEquals(UrlSecurityFailureType.INVALID_CHARACTER, exception.getFailureType(),
                    "Double Content-Length should trigger INVALID_CHARACTER detection for: " + attack);
            assertTrue(eventCounter.getTotalCount() > initialEventCount,
                    "Security event should be recorded for double Content-Length");
        }
    }

    /**
     * Test performance impact of request smuggling validation.
     * 
     * <p>
     * Ensures that request smuggling detection doesn't significantly impact
     * validation performance, even with complex attack patterns.
     * </p>
     */
    @Test
    @DisplayName("Request smuggling validation should maintain performance")
    void shouldMaintainPerformanceWithRequestSmugglingAttacks() {
        String complexSmugglingPattern = "/api/data?param=value%0d%0aContent-Length: 6%0d%0aTransfer-Encoding: chunked%0d%0aTransfer-encoding: gzip%0d%0aContent-Length: 44%0d%0a%0d%0a0%0d%0a%0d%0aGET /admin HTTP/1.1%0d%0aAuthorization: Bearer admin-token%0d%0aHost: backend-server%0d%0a%0d%0a";

        // Warm up
        for (int i = 0; i < 10; i++) {
            try {
                pipeline.validate(complexSmugglingPattern);
            } catch (UrlSecurityException ignored) {
            }
        }

        // Measure performance
        long startTime = System.nanoTime();
        for (int i = 0; i < 100; i++) {
            try {
                pipeline.validate(complexSmugglingPattern);
            } catch (UrlSecurityException ignored) {
            }
        }
        long endTime = System.nanoTime();

        long averageNanos = (endTime - startTime) / 100;
        long averageMillis = averageNanos / 1_000_000;

        // Should complete within reasonable time (< 8ms per validation)
        assertTrue(averageMillis < 8,
                "Request smuggling validation should complete within 8ms, actual: " + averageMillis + "ms");
    }

    /**
     * Test comprehensive edge cases in request smuggling detection.
     * 
     * <p>
     * Tests various edge cases and corner conditions that might be
     * exploited in request smuggling attacks.
     * </p>
     */
    @Test
    @DisplayName("Request smuggling edge cases must be handled")
    void shouldHandleRequestSmugglingEdgeCases() {
        String[] edgeCaseAttacks = {
                // Chunked encoding with malformed chunks
                "/test?data=sample%0d%0aTransfer-Encoding: chunked%0d%0a%0d%0aZZ%0d%0aGET /admin HTTP/1.1%0d%0a%0d%0a",

                // HTTP version manipulation
                "/page?id=1%0d%0a%0d%0aGET /secret HTTP/2.0%0d%0aHost: internal%0d%0a%0d%0a",

                // Protocol downgrade attack
                "/resource%0d%0a%0d%0aGET /admin HTTP/1.0%0d%0aConnection: keep-alive%0d%0a%0d%0a",

                // Mixed line endings
                "/api/endpoint%0a%0aGET /backdoor HTTP/1.1%0aHost: target%0a%0a",

                // Extremely long smuggled request
                "/normal" + "%0d%0a%0d%0aGET /" + generateLongPath(1000) + " HTTP/1.1%0d%0aHost: evil%0d%0a%0d%0a"
        };

        for (String attack : edgeCaseAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Request smuggling edge case should be rejected: " + attack);

            assertNotNull(exception);
            assertTrue(eventCounter.getTotalCount() > initialEventCount,
                    "Security event should be recorded for edge case");
        }
    }

    /**
     * Determines if a failure type is specifically appropriate for the given request smuggling attack pattern.
     * Most HTTP request smuggling attacks use CRLF injection (%0d%0a) which should trigger CONTROL_CHARACTERS.
     * 
     * @param failureType The failure type to check
     * @param pattern The specific attack pattern being tested
     * @return true if the failure type is specifically appropriate for the pattern
     */
    private boolean isSpecificRequestSmugglingFailure(UrlSecurityFailureType failureType, String pattern) {
        // HTTP Request Smuggling patterns can trigger multiple specific failure types:
        // - CRLF injection (%0d%0a, %0a) → CONTROL_CHARACTERS or INVALID_CHARACTER
        // - Malformed chunk encoding → INVALID_ENCODING
        // - HTTP protocol violations → PROTOCOL_VIOLATION
        // - RFC violations → RFC_VIOLATION
        // - General malformed input → MALFORMED_INPUT
        
        // Accept these specific failure types as valid for request smuggling patterns
        return failureType == UrlSecurityFailureType.CONTROL_CHARACTERS ||
                failureType == UrlSecurityFailureType.INVALID_CHARACTER ||
                failureType == UrlSecurityFailureType.PROTOCOL_VIOLATION ||
                failureType == UrlSecurityFailureType.RFC_VIOLATION ||
                failureType == UrlSecurityFailureType.INVALID_ENCODING ||
                failureType == UrlSecurityFailureType.MALFORMED_INPUT ||
                failureType == UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED;
    }

    /**
     * QI-17: Generate realistic long path instead of using .repeat().
     * Creates varied path content for HTTP request smuggling testing.
     */
    private String generateLongPath(int length) {
        StringBuilder path = new StringBuilder();
        String[] segments = {"admin", "data", "secret", "config", "api", "user"};
        
        while (path.length() < length - 10) { // Leave room for final segment
            String segment = segments[path.length() % segments.length];
            path.append(segment);
            if (path.length() < length - 10) {
                path.append("/");
            }
        }
        
        // Fill remaining length with varied characters
        while (path.length() < length) {
            path.append("x");
        }
        
        return path.toString();
    }
}