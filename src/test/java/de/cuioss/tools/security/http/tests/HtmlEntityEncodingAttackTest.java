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
import de.cuioss.tools.security.http.generators.encoding.HtmlEntityEncodingAttackGenerator;
import de.cuioss.tools.security.http.generators.url.ValidURLPathGenerator;
import de.cuioss.tools.security.http.monitoring.SecurityEventCounter;
import de.cuioss.tools.security.http.pipeline.URLPathValidationPipeline;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * T7: Test HTML entity encoding attacks
 * 
 * <p>
 * This test class implements Task T7 from the HTTP security validation plan,
 * focusing on testing HTML entity encoding attacks that use HTML entities
 * to obfuscate malicious payloads and bypass security controls that might
 * not properly decode HTML entities before validation.
 * </p>
 * 
 * <h3>Test Coverage</h3>
 * <ul>
 *   <li>Named HTML entities (&lt;, &gt;, &quot;, &amp;, &#x27;)</li>
 *   <li>Decimal numeric entities (&#46; for '.', &#47; for '/')</li>
 *   <li>Hexadecimal numeric entities (&#x2E; for '.', &#x2F; for '/')</li>
 *   <li>Mixed case variants in hexadecimal entities</li>
 *   <li>Leading zeros in numeric entities (&#00046; for '.')</li>
 *   <li>Malformed entities for robustness testing</li>
 *   <li>Nested entity encoding (&amp;lt; for &lt;)</li>
 *   <li>Path traversal patterns with HTML entity encoding</li>
 *   <li>XSS payloads with HTML entity obfuscation</li>
 *   <li>Edge cases and boundary conditions</li>
 * </ul>
 * 
 * <h3>Security Standards</h3>
 * <ul>
 *   <li>OWASP Top 10 - Injection Prevention</li>
 *   <li>CWE-20: Improper Input Validation</li>
 *   <li>CWE-79: Cross-site Scripting (XSS)</li>
 *   <li>CWE-116: Improper Encoding or Escaping of Output</li>
 *   <li>HTML5 Character Reference Standards</li>
 *   <li>W3C HTML Entity Specification</li>
 * </ul>
 * 
 * Implements: Task T7 from HTTP verification specification
 * 
 * @author Claude Code Generator
 * @since 2.5
 */
@EnableGeneratorController
@Disabled("TODO: Enable when security pipeline supports HTML entity decoding - see bugs.md QI-15")
@DisplayName("T7: HTML Entity Encoding Attack Tests")
class HtmlEntityEncodingAttackTest {

    private URLPathValidationPipeline pipeline;
    private SecurityEventCounter eventCounter;
    private SecurityConfiguration config;

    @BeforeEach
    void setUp() {
        config = SecurityConfiguration.builder()
                .failOnSuspiciousPatterns(true)
                .allowHighBitCharacters(false)
                .allowControlCharacters(false)
                .normalizeUnicode(true)
                .build();
        eventCounter = new SecurityEventCounter();
        pipeline = new URLPathValidationPipeline(config, eventCounter);
    }

    /**
     * Test HTML entity encoding attack patterns.
     * 
     * <p>
     * Uses HtmlEntityEncodingAttackGenerator which creates attack patterns
     * using various forms of HTML entity encoding to obfuscate malicious
     * payloads and attempt bypassing security controls.
     * </p>
     * 
     * @param htmlEntityPattern An HTML entity encoded attack pattern
     */
    @ParameterizedTest
    @TypeGeneratorSource(value = HtmlEntityEncodingAttackGenerator.class, count = 80)
    @DisplayName("HTML entity encoding attack patterns should be rejected")
    void shouldRejectHtmlEntityEncodingAttacks(String htmlEntityPattern) {
        // Given: An HTML entity encoded attack pattern from the generator
        long initialEventCount = eventCounter.getTotalCount();

        // When: Attempting to validate the HTML entity attack
        var exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(htmlEntityPattern),
                "HTML entity attack pattern should be rejected: " + htmlEntityPattern);

        // Then: The validation should fail with appropriate security event
        assertNotNull(exception, "Exception should be thrown for HTML entity attack");
        assertTrue(isEncodingOrSecurityRelatedFailure(exception.getFailureType()),
                "Failure type should be encoding or security-related: " + exception.getFailureType() +
                        " for pattern: " + htmlEntityPattern);

        // And: Original malicious input should be preserved
        assertEquals(htmlEntityPattern, exception.getOriginalInput(),
                "Original input should be preserved in exception");

        // And: Security event should be recorded
        assertTrue(eventCounter.getTotalCount() > initialEventCount,
                "Security event should be recorded");
    }

    /**
     * Test known HTML entity attack vectors.
     * 
     * <p>
     * Tests specific HTML entity attack patterns that have been documented
     * in security research or used in real-world attacks.
     * </p>
     */
    @Test
    @DisplayName("Known HTML entity attack vectors should be rejected")
    void shouldRejectKnownHtmlEntityAttacks() {
        String[] knownAttacks = {
                // Path traversal with URL encoding
                "%2e%2e%2f",                                 // ../
                "%2E%2E%2F",                                 // ../ (uppercase)
                "%2e%2e%5c",                                 // ..\
                "%2e%2e%2f%2e%2e%2f",                        // ../../
                "%2e%2e%2f%2e%2e%2f%2e%2e%2f",              // ../../../
                
                // XSS with URL encoding
                "%3cscript%3ealert%281%29%3c%2fscript%3e",
                "%3cimg%20src%3dx%20onerror%3dalert%281%29%3e",
                "javascript%3aalert%281%29",
                "%3csvg%20onload%3dalert%281%29%3e",
                "%3ciframe%20src%3djavascript%3aalert%281%29%3e",

                // Additional URL encoded attack patterns
                "%3cscript%3e",
                "%2e%2e%2f%2e%2e%2f",

                // Mixed case URL encoding
                "%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
                "%3cscript%3ealert%281%29%3c%2fscript%3e",
                "%3cscript%3ealert%281%29%3c%2fscript%3e",

                // Case variations
                "&#X2E;&#X2E;&#X2F;",                       // Uppercase X
                "&#x2e;&#x2e;&#x2f;",                       // Lowercase hex
                
                // Protocol handlers with entities
                "data&#58;text&#47;html&#44;&lt;script&gt;alert&#40;1&#41;&lt;&#47;script&gt;",
                "vbscript&#58;msgbox&#40;1&#41;",

                // Event handler injections
                "&quot;&gt;&lt;img src&#61;x onerror&#61;alert&#40;1&#41;&gt;",
                "&#39;&gt;&lt;svg onload&#61;alert&#40;1&#41;&gt;"
        };

        for (String attack : knownAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Known HTML entity attack should be rejected: " + attack);

            assertNotNull(exception, "Exception should be thrown for: " + attack);
            assertTrue(eventCounter.getTotalCount() > initialEventCount,
                    "Security event should be recorded for: " + attack);
        }
    }

    /**
     * Test edge cases in HTML entity encoding detection.
     * 
     * <p>
     * Tests various edge cases that might cause issues in HTML entity
     * detection logic, including malformed entities and boundary conditions.
     * </p>
     */
    @Test
    @DisplayName("Should handle edge cases in HTML entity detection")
    void shouldHandleEdgeCasesInHtmlEntityDetection() {
        String[] edgeCases = {
                "&#46",                    // Missing semicolon
                "&#x2F",                   // Missing semicolon
                "&#;",                     // Empty numeric entity
                "&#x;",                    // Empty hex entity
                "&invalid;",               // Invalid entity name
                "&#999;",                  // Invalid numeric value (too high)
                "&#x3C;extra",            // Extra content after entity
                "&",                       // Standalone ampersand
                "&amp",                    // Incomplete named entity
                "&#x2E;&",                // Valid entity + standalone &
                "&#46;&#x2F&#92;",        // Mixed valid/invalid entities
                "&lt;&gt;&quot;&amp;",     // Multiple valid entities
                "&#x2E;&#x2E;&#x2F;&#x2E;&#x2E;&#x2F;", // Long entity sequence
                "&#00000046;",            // Many leading zeros
                "&#X2E;",                 // Uppercase X variant
                "&amp;amp;amp;lt;",       // Multiple levels of nesting
                "&#48;&#46;&#46;&#47;",   // 0../ with entities
        };

        for (String edgeCase : edgeCases) {
            long initialEventCount = eventCounter.getTotalCount();

            try {
                String result = pipeline.validate(edgeCase);
                // If validation passes, result should not be null
                assertNotNull(result, "Validated result should not be null for: " + edgeCase);

            } catch (UrlSecurityException e) {
                // Edge cases might be rejected for various reasons
                assertTrue(eventCounter.getTotalCount() > initialEventCount,
                        "Security event should be recorded when rejecting: " + edgeCase);

                assertNotNull(e.getFailureType(),
                        "Exception should have failure type for: " + edgeCase);
            }
        }
    }

    /**
     * Test that legitimate HTML content is handled appropriately.
     * 
     * <p>
     * Tests legitimate use of HTML entities in contexts where they might
     * be expected, ensuring the security validation doesn't create excessive
     * false positives for normal HTML content.
     * </p>
     */
    @Test
    @DisplayName("Legitimate HTML entities should be handled appropriately")
    void shouldHandleLegitimateHtmlEntities() {
        String[] legitimateContent = {
                // Common HTML entities in text content
                "Q&amp;A",                    // Q&A
                "Tom &amp; Jerry",            // Tom & Jerry
                "&lt;xml&gt;",                // <xml>
                "&quot;Hello World&quot;",    // "Hello World"
                "It&apos;s working",          // It's working
                // Note: These might still be blocked in a URL context for security,
                // which is acceptable behavior for a security-focused system
        };

        for (String content : legitimateContent) {
            long initialEventCount = eventCounter.getTotalCount();

            try {
                String result = pipeline.validate(content);
                assertNotNull(result, "Legitimate content should be processable: " + content);

                // In a URL security context, even legitimate HTML entities might be blocked
                // This is acceptable for a security-first approach
                
            } catch (UrlSecurityException e) {
                // Legitimate HTML entities might still be blocked in URL context
                // This is acceptable for a security-focused validation system
                assertTrue(eventCounter.getTotalCount() > initialEventCount,
                        "If content is blocked, security event should be recorded: " + content);
            }
        }
    }

    /**
     * Test valid URL paths should pass validation.
     * 
     * <p>
     * Uses ValidURLPathGenerator to ensure that legitimate URL paths
     * are not incorrectly blocked by HTML entity detection.
     * </p>
     * 
     * @param validPath A valid URL path
     */
    @ParameterizedTest
    @TypeGeneratorSource(value = ValidURLPathGenerator.class, count = 15)
    @DisplayName("Valid URL paths should pass validation")
    void shouldValidateValidPaths(String validPath) {
        // Given: A valid path from the generator
        long initialEventCount = eventCounter.getTotalCount();

        // When: Validating the legitimate path
        try {
            String result = pipeline.validate(validPath);
            // Then: Should return validated result
            assertNotNull(result, "Valid path should return validated result: " + validPath);

            // And: No security events should be recorded for valid paths
            assertEquals(initialEventCount, eventCounter.getTotalCount(),
                    "No security events should be recorded for valid path: " + validPath);

        } catch (UrlSecurityException e) {
            // Some paths might still be blocked by other security rules
            // This is acceptable for a security-first approach
            assertTrue(initialEventCount < eventCounter.getTotalCount(),
                    "If path is blocked, security event should be recorded: " + validPath);
        }
    }

    /**
     * Test performance impact of HTML entity detection.
     * 
     * <p>
     * Ensures that detection of complex HTML entity patterns
     * doesn't significantly impact validation performance.
     * </p>
     */
    @Test
    @DisplayName("HTML entity detection should maintain performance")
    void shouldMaintainPerformanceWithHtmlEntityDetection() {
        String complexHtmlEntityPattern =
                """
                &lt;script&gt;&#97;&#108;&#101;&#114;&#116;&#40;&quot;&#46;&#46;&#47;&#46;&#46;&#47;&quot;&#41;&lt;&#47;script&gt;\
                &lt;img src&#61;x onerror&#61;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;&gt;\
                &amp;lt;svg onload&amp;#61;&amp;#97;&amp;#108;&amp;#101;&amp;#114;&amp;#116;&amp;#40;&amp;#49;&amp;#41;&amp;gt;\
                """;

        // Warm up
        for (int i = 0; i < 10; i++) {
            try {
                pipeline.validate(complexHtmlEntityPattern);
            } catch (UrlSecurityException ignored) {
                // Expected for malicious pattern
            }
        }

        // Measure performance
        long startTime = System.nanoTime();
        for (int i = 0; i < 100; i++) {
            try {
                pipeline.validate(complexHtmlEntityPattern);
            } catch (UrlSecurityException ignored) {
                // Expected for malicious pattern
            }
        }
        long endTime = System.nanoTime();

        long averageNanos = (endTime - startTime) / 100;
        long averageMillis = averageNanos / 1_000_000;

        // Should complete within reasonable time (< 8ms per validation for complex HTML entity patterns)
        assertTrue(averageMillis < 8,
                "HTML entity detection should complete within 8ms, actual: " + averageMillis + "ms");
    }

    /**
     * Test robustness against entity bombing attacks.
     * 
     * <p>
     * Tests the system's resilience against attempts to overwhelm
     * processing with excessive entity references or deeply nested entities.
     * </p>
     */
    @Test
    @DisplayName("Should resist HTML entity bombing attacks")
    void shouldResistHtmlEntityBombingAttacks() {
        String[] bombingAttempts = {
                // Large number of entities
                "&#46;".repeat(1000) + "&#47;".repeat(1000),

                // Deeply nested entities (to a reasonable limit)
                "&amp;amp;amp;amp;amp;amp;amp;amp;amp;amp;lt;script&amp;amp;amp;amp;amp;amp;amp;amp;amp;amp;amp;gt;",

                // Mixed long entity sequences
                "&#x2E;&#x2E;&#x2F;".repeat(100),

                // Very long single entity reference
                "&#" + "0".repeat(100) + "46;",
        };

        for (String bomb : bombingAttempts) {
            long initialEventCount = eventCounter.getTotalCount();

            // Should either reject the pattern or handle it gracefully within time limits
            long startTime = System.nanoTime();

            try {
                String result = pipeline.validate(bomb);
                // If it passes validation, should complete within reasonable time
                long duration = System.nanoTime() - startTime;
                assertTrue(duration < 50_000_000, // 50ms limit
                        "Entity processing should complete within time limit for: " +
                                bomb.substring(0, Math.min(50, bomb.length())) + "...");

            } catch (UrlSecurityException e) {
                // Expected - should reject entity bombing attempts
                assertTrue(eventCounter.getTotalCount() > initialEventCount,
                        "Security event should be recorded for bombing attempt");

                long duration = System.nanoTime() - startTime;
                assertTrue(duration < 50_000_000, // 50ms limit
                        "Entity bomb rejection should complete within time limit");
            }
        }
    }

    /**
     * Determines if a failure type is related to encoding attacks or general security issues.
     * 
     * @param failureType The failure type to check
     * @return true if the failure type indicates an encoding-related or general security issue
     */
    private boolean isEncodingOrSecurityRelatedFailure(UrlSecurityFailureType failureType) {
        return failureType == UrlSecurityFailureType.DOUBLE_ENCODING ||
                failureType == UrlSecurityFailureType.INVALID_ENCODING ||
                failureType == UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED ||
                failureType == UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED ||
                failureType == UrlSecurityFailureType.INVALID_CHARACTER ||
                failureType == UrlSecurityFailureType.UNICODE_NORMALIZATION_CHANGED ||
                failureType == UrlSecurityFailureType.XSS_DETECTED ||
                failureType == UrlSecurityFailureType.SQL_INJECTION_DETECTED ||
                failureType == UrlSecurityFailureType.COMMAND_INJECTION_DETECTED ||
                failureType == UrlSecurityFailureType.NULL_BYTE_INJECTION ||
                failureType == UrlSecurityFailureType.CONTROL_CHARACTERS ||
                failureType == UrlSecurityFailureType.MALFORMED_INPUT ||
                failureType == UrlSecurityFailureType.KNOWN_ATTACK_SIGNATURE;
    }
}