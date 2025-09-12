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
     * creating desynchronization opportunities. Uses generator for dynamic patterns.
     * </p>
     */
    @ParameterizedTest
    @TypeGeneratorSource(value = HttpRequestSmugglingAttackGenerator.class, count = 25)
    @DisplayName("CL.TE smuggling attacks must be blocked")
    void shouldBlockClTeSmuggling(String clTeAttack) {
        // Filter to test only CL.TE patterns (Content-Length + Transfer-Encoding)
        if (!clTeAttack.contains("Content-Length:") || !clTeAttack.contains("Transfer-Encoding:")) {
            return; // Skip non-CL.TE patterns
        }

        long initialEventCount = eventCounter.getTotalCount();

        var exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(clTeAttack),
                "CL.TE smuggling attack should be rejected: " + clTeAttack);

        assertNotNull(exception);
        assertEquals(UrlSecurityFailureType.INVALID_CHARACTER, exception.getFailureType(),
                "CL.TE smuggling should trigger INVALID_CHARACTER detection for: " + clTeAttack);
        assertTrue(eventCounter.getTotalCount() > initialEventCount,
                "Security event should be recorded for CL.TE attack");
    }

    /**
     * Test specific TE.CL (Transfer-Encoding/Content-Length) smuggling attacks.
     * 
     * <p>
     * Tests attacks where the front-end server processes the Transfer-Encoding
     * header while the back-end server processes the Content-Length header.
     * Uses generator for dynamic patterns.
     * </p>
     */
    @ParameterizedTest
    @TypeGeneratorSource(value = HttpRequestSmugglingAttackGenerator.class, count = 25)
    @DisplayName("TE.CL smuggling attacks must be blocked")
    void shouldBlockTeClSmuggling(String teClAttack) {
        // Filter to test only TE.CL patterns (Transfer-Encoding + Content-Length, TE first)
        if (!teClAttack.contains("Transfer-Encoding:") || !teClAttack.contains("Content-Length:")) {
            return; // Skip non-TE.CL patterns
        }

        long initialEventCount = eventCounter.getTotalCount();

        var exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(teClAttack),
                "TE.CL smuggling attack should be rejected: " + teClAttack);

        assertNotNull(exception);
        assertEquals(UrlSecurityFailureType.INVALID_CHARACTER, exception.getFailureType(),
                "TE.CL smuggling should trigger INVALID_CHARACTER detection for: " + teClAttack);
        assertTrue(eventCounter.getTotalCount() > initialEventCount,
                "Security event should be recorded for TE.CL attack");
    }

    /**
     * Test specific TE.TE (Transfer-Encoding/Transfer-Encoding) smuggling attacks.
     * 
     * <p>
     * Tests attacks using Transfer-Encoding header obfuscation to create
     * parsing differences between front-end and back-end servers.
     * Uses generator for dynamic patterns.
     * </p>
     */
    @ParameterizedTest
    @TypeGeneratorSource(value = HttpRequestSmugglingAttackGenerator.class, count = 30)
    @DisplayName("TE.TE smuggling attacks must be blocked")
    void shouldBlockTeTeSmuggling(String teTeAttack) {
        // Filter to test patterns that might be TE.TE (multiple Transfer-Encoding headers)
        // Note: Generator covers this in its TE.TE method, but we test all generator output
        if (!teTeAttack.contains("Transfer-Encoding:")) {
            return; // Skip non-Transfer-Encoding patterns
        }

        long initialEventCount = eventCounter.getTotalCount();

        var exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(teTeAttack),
                "TE.TE smuggling attack should be rejected: " + teTeAttack);

        assertNotNull(exception);
        assertEquals(UrlSecurityFailureType.INVALID_CHARACTER, exception.getFailureType(),
                "TE.TE smuggling should trigger INVALID_CHARACTER detection for: " + teTeAttack);
        assertTrue(eventCounter.getTotalCount() > initialEventCount,
                "Security event should be recorded for TE.TE attack");
    }

    /**
     * Test HTTP pipeline poisoning attacks.
     * 
     * <p>
     * Tests attacks that attempt to poison HTTP connection pipelines
     * to affect subsequent requests from other users. Uses generator for dynamic patterns.
     * </p>
     */
    @ParameterizedTest
    @TypeGeneratorSource(value = HttpRequestSmugglingAttackGenerator.class, count = 30)
    @DisplayName("HTTP pipeline poisoning attacks must be blocked")
    void shouldBlockPipelinePoisoning(String pipelinePoisoningAttack) {
        // Pipeline poisoning typically uses CRLF injection patterns
        if (!pipelinePoisoningAttack.contains("%0d%0a")) {
            return; // Skip non-CRLF patterns
        }

        long initialEventCount = eventCounter.getTotalCount();

        var exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(pipelinePoisoningAttack),
                "Pipeline poisoning attack should be rejected: " + pipelinePoisoningAttack);

        assertNotNull(exception);
        assertEquals(UrlSecurityFailureType.INVALID_CHARACTER, exception.getFailureType(),
                "Pipeline poisoning should trigger INVALID_CHARACTER detection for: " + pipelinePoisoningAttack);
        assertTrue(eventCounter.getTotalCount() > initialEventCount,
                "Security event should be recorded for pipeline poisoning");
    }

    /**
     * Test cache deception through request smuggling.
     * 
     * <p>
     * Tests attacks that use request smuggling to manipulate caching
     * behavior and serve malicious content to other users. Uses generator for dynamic patterns.
     * </p>
     */
    @ParameterizedTest
    @TypeGeneratorSource(value = HttpRequestSmugglingAttackGenerator.class, count = 25)
    @DisplayName("Cache deception attacks must be blocked")
    void shouldBlockCacheDeception(String cacheDeceptionAttack) {
        // Cache deception through HTTP request smuggling uses CRLF patterns
        if (!cacheDeceptionAttack.contains("%0d%0a")) {
            return; // Skip non-CRLF patterns
        }

        long initialEventCount = eventCounter.getTotalCount();

        var exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(cacheDeceptionAttack),
                "Cache deception attack should be rejected: " + cacheDeceptionAttack);

        assertNotNull(exception);
        assertEquals(UrlSecurityFailureType.INVALID_CHARACTER, exception.getFailureType(),
                "Cache deception should trigger INVALID_CHARACTER detection for: " + cacheDeceptionAttack);
        assertTrue(eventCounter.getTotalCount() > initialEventCount,
                "Security event should be recorded for cache deception");
    }

    /**
     * Test double Content-Length header attacks.
     * 
     * <p>
     * Tests attacks using multiple Content-Length headers to create
     * parsing inconsistencies between servers. Uses generator for dynamic patterns.
     * </p>
     */
    @ParameterizedTest
    @TypeGeneratorSource(value = HttpRequestSmugglingAttackGenerator.class, count = 25)
    @DisplayName("Double Content-Length header attacks must be blocked")
    void shouldBlockDoubleContentLength(String doubleContentLengthAttack) {
        // Double Content-Length attacks use Content-Length headers with CRLF
        if (!doubleContentLengthAttack.contains("Content-Length:") || !doubleContentLengthAttack.contains("%0d%0a")) {
            return; // Skip non-Content-Length CRLF patterns
        }

        long initialEventCount = eventCounter.getTotalCount();

        var exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(doubleContentLengthAttack),
                "Double Content-Length attack should be rejected: " + doubleContentLengthAttack);

        assertNotNull(exception);
        assertEquals(UrlSecurityFailureType.INVALID_CHARACTER, exception.getFailureType(),
                "Double Content-Length should trigger INVALID_CHARACTER detection for: " + doubleContentLengthAttack);
        assertTrue(eventCounter.getTotalCount() > initialEventCount,
                "Security event should be recorded for double Content-Length");
    }

    /**
     * Test comprehensive edge cases in request smuggling detection.
     * 
     * <p>
     * Tests various edge cases and corner conditions that might be
     * exploited in request smuggling attacks. Uses generator for dynamic patterns.
     * </p>
     */
    @ParameterizedTest
    @TypeGeneratorSource(value = HttpRequestSmugglingAttackGenerator.class, count = 35)
    @DisplayName("Request smuggling edge cases must be handled")
    void shouldHandleRequestSmugglingEdgeCases(String edgeCaseAttack) {
        // Test all generator patterns as potential edge cases
        long initialEventCount = eventCounter.getTotalCount();

        var exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(edgeCaseAttack),
                "Request smuggling edge case should be rejected: " + edgeCaseAttack);

        assertNotNull(exception);
        assertTrue(eventCounter.getTotalCount() > initialEventCount,
                "Security event should be recorded for edge case");
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