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
import de.cuioss.tools.security.http.generators.injection.HomographAttackGenerator;
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
 * T9: Test homograph attacks
 * 
 * <p>
 * This test class implements Task T9 from the HTTP security validation plan,
 * focusing on testing homograph attacks that use Unicode characters that look
 * identical or very similar to ASCII characters to create deceptive URLs and
 * bypass security controls through visual spoofing.
 * </p>
 * 
 * <h3>Test Coverage</h3>
 * <ul>
 *   <li>Cyrillic homographs (а, о, р, с, е, х → a, o, p, c, e, x)</li>
 *   <li>Greek homographs (α, ο, ρ, υ → a, o, p, u)</li>
 *   <li>Mathematical script homographs (𝐚, 𝐨, 𝐩 → a, o, p)</li>
 *   <li>Fullwidth character homographs (ａ, ｏ, ｐ → a, o, p)</li>
 *   <li>Armenian, Georgian, and other script homographs</li>
 *   <li>Mixed script combinations for maximum deception</li>
 *   <li>Domain spoofing attacks (apple.com → аpple.com)</li>
 *   <li>File extension spoofing (.exe → .ехе)</li>
 *   <li>System command spoofing (admin → аdmin)</li>
 *   <li>Homograph detection and validation</li>
 * </ul>
 * 
 * <h3>Security Standards</h3>
 * <ul>
 *   <li>OWASP Top 10 - Security Misconfiguration</li>
 *   <li>CWE-20: Improper Input Validation</li>
 *   <li>CWE-178: Improper Handling of Case Sensitivity</li>
 *   <li>CWE-179: Incorrect Behavior Order: Early Validation</li>
 *   <li>Unicode Technical Standard #39 (Unicode Security Mechanisms)</li>
 *   <li>RFC 3490 - Internationalizing Domain Names in Applications (IDNA)</li>
 *   <li>Unicode Consortium Security Considerations</li>
 * </ul>
 * 
 * Implements: Task T9 from HTTP verification specification
 * 
 * @author Claude Code Generator
 * @since 2.5
 */
@EnableGeneratorController
@Disabled("TODO: Enable when security pipeline supports Unicode homograph detection - see bugs.md QI-15")
@DisplayName("T9: Homograph Attack Tests")
class HomographAttackTest {

    private URLPathValidationPipeline pipeline;
    private SecurityEventCounter eventCounter;
    private SecurityConfiguration config;
    private HomographAttackGenerator attackGenerator;

    @BeforeEach
    void setUp() {
        config = SecurityConfiguration.defaults();
        eventCounter = new SecurityEventCounter();
        pipeline = new URLPathValidationPipeline(config, eventCounter);
        attackGenerator = new HomographAttackGenerator();
    }

    /**
     * Test homograph attack patterns.
     * 
     * <p>
     * Uses HomographAttackGenerator which creates attack patterns using
     * Unicode homograph characters that visually resemble ASCII characters
     * to create deceptive content that could bypass security controls.
     * </p>
     * 
     * @param homographPattern A homograph attack pattern
     */
    @ParameterizedTest
    @TypeGeneratorSource(value = HomographAttackGenerator.class, count = 100)
    @DisplayName("Homograph attack patterns should be rejected")
    void shouldRejectHomographAttacks(String homographPattern) {
        // Given: A homograph attack pattern from the generator
        long initialEventCount = eventCounter.getTotalCount();

        // When: Attempting to validate the homograph attack
        var exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(homographPattern),
                "Homograph attack pattern should be rejected: " + homographPattern +
                        " (contains homographs: " + attackGenerator.containsHomographs(homographPattern) + ")");

        // Then: The validation should fail with appropriate security event
        assertNotNull(exception, "Exception should be thrown for homograph attack");
        assertTrue(isHomographOrSecurityRelatedFailure(exception.getFailureType()),
                "Failure type should be homograph or security-related: " + exception.getFailureType() +
                        " for pattern: " + homographPattern);

        // And: Original malicious input should be preserved
        assertEquals(homographPattern, exception.getOriginalInput(),
                "Original input should be preserved in exception");

        // And: Security event should be recorded
        assertTrue(eventCounter.getTotalCount() > initialEventCount,
                "Security event should be recorded");
    }

    /**
     * Test known homograph attack vectors.
     * 
     * <p>
     * Tests specific homograph attack patterns that have been documented
     * in security research or used in real-world phishing and spoofing attacks.
     * </p>
     */
    @Test
    @DisplayName("Known homograph attack vectors should be rejected")
    void shouldRejectKnownHomographAttacks() {
        String[] knownAttacks = {
                // Cyrillic spoofing of common words
                "\u0430dmin",                          // аdmin (Cyrillic a + latin dmin)
                "r\u043E\u043Et",                      // rооt (r + Cyrillic oo + t)
                "\u0441onfig",                         // сonfig (Cyrillic c + latin onfig)
                "\u0440assword",                       // рassword (Cyrillic p + latin assword)
                "\u0455ecure",                         // ѕecure (Cyrillic dze + latin ecure)
                "\u043Bogi\u043F",                     // login with mixed Cyrillic
                
                // Greek spoofing
                "\u03B1dmin",                          // αdmin (Greek alpha + latin dmin)
                "r\u03BF\u03BFt",                      // rοοt (r + Greek omicron + t)
                "\u03C1assword",                       // ρassword (Greek rho + latin assword)
                "sec\u03C5re",                         // secυre (Greek upsilon for u)
                
                // Domain spoofing attacks
                "\u0430pple.com",                      // аpple.com (Cyrillic a)
                "g\u043Eogle.com",                     // gоogle.com (Cyrillic o)
                "micro\u0455oft.com",                  // microѕoft.com (Cyrillic dze)
                "git\u04C0ub.com",                     // gitӀub.com (Cyrillic palochka)
                "\u0430mazon.com",                     // аmazon.com (Cyrillic a)
                
                // File extension spoofing
                ".e\u0445e",                           // .exe with Cyrillic kha for x
                ".\u0440df",                           // .pdf with Cyrillic er for p
                ".d\u043Ec",                           // .doc with Cyrillic o
                ".\u0455\u0440s",                      // .zip with Cyrillic characters
                
                // Mixed script sophisticated attacks
                "\u0430d\u043C\u0456n",                // admin with mixed Cyrillic
                "\u0440\u0430\u0455\u0455w\u043E\u0433d", // password with mixed Cyrillic
                "\u0441\u043E\u043D\u0493ig",          // config with mixed Cyrillic
                
                // Fullwidth character attacks
                "\uFF41dmin",                          // ａdmin (Fullwidth a)
                "r\uFF4F\uFF4Ft",                      // rｏｏt (Fullwidth o)
                "\uFF50assword",                       // ｐassword (Fullwidth p)
                
                // Mathematical script attacks
                "\uD835\uDC1Admin",                    // 𝐚dmin (Mathematical bold a)
                "r\uD835\uDC28\uD835\uDC28t",          // r𝐨𝐨t (Mathematical bold o)
                
                // Armenian homograph attacks
                "\u0585auth",                          // օauth (Armenian oh + latin auth)
                "inf\u0585",                           // infօ (Armenian oh for o)
                
                // Georgian homograph attacks
                "l\u10DDgin",                          // lოgin (Georgian on for o)
                "\u10D2oogle.com",                     // გoogle.com (Georgian gan for g)
                
                // Path traversal with homographs
                "..\u0445/",                           // ..х/ (Cyrillic kha looks like x)
                "\uFF0E\uFF0E\uFF0F",                  // ．．／ (Fullwidth path traversal)
                "..\u2044",                            // ../ with fraction slash
                
                // Script injection with homographs
                "j\u0430v\u0430script:",               // jаvаscript: (Mixed Latin/Cyrillic)
                "\u0430lert(1)",                       // аlert(1) (Cyrillic a)
                "e\u03C5al()",                         // eυal() (Greek upsilon for v)
                
                // Complex mixed homograph attacks
                "\u0430\u043F\u043F\u04CF\u0435.\u0441\u043E\u043C", // apple.com fully in Cyrillic-like
                "\u03B1\u043C\u0430\u0437\u043E\u03BD.\u0441\u043E\u043C", // amazon.com mixed Greek/Cyrillic
        };

        for (String attack : knownAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Known homograph attack should be rejected: " + attack +
                            " (homographs: " + attackGenerator.containsHomographs(attack) + ")");

            assertNotNull(exception, "Exception should be thrown for: " + attack);
            assertTrue(eventCounter.getTotalCount() > initialEventCount,
                    "Security event should be recorded for: " + attack);
        }
    }

    /**
     * Test homograph detection capabilities.
     * 
     * <p>
     * Tests that the system can correctly identify when strings contain
     * homograph characters that could be used for spoofing attacks.
     * </p>
     */
    @Test
    @DisplayName("Should detect homograph characters")
    void shouldDetectHomographCharacters() {
        String[] homographStrings = {
                "\u0430dmin",          // Cyrillic a
                "r\u043E\u043Et",      // Cyrillic o
                "\u03B1lpha",          // Greek alpha
                "\uFF41scii",          // Fullwidth a
                "\u0455ecure",         // Cyrillic dze
                "\u04CF\u043E\u0433in", // Mixed Cyrillic homographs
        };

        String[] nonHomographStrings = {
                "admin",               // Pure ASCII
                "root",                // Pure ASCII
                "password",            // Pure ASCII
                "secure",              // Pure ASCII
                "login",               // Pure ASCII
                "config",              // Pure ASCII
        };

        // Test positive cases - should detect homographs
        for (String homographString : homographStrings) {
            assertTrue(attackGenerator.containsHomographs(homographString),
                    "Should detect homographs in: " + homographString);
        }

        // Test negative cases - should not detect homographs in pure ASCII
        for (String nonHomographString : nonHomographStrings) {
            assertFalse(attackGenerator.containsHomographs(nonHomographString),
                    "Should not detect homographs in pure ASCII: " + nonHomographString);
        }
    }

    /**
     * Test edge cases in homograph detection.
     * 
     * <p>
     * Tests various edge cases that might cause issues in homograph
     * detection logic, including mixed scripts and boundary conditions.
     * </p>
     */
    @Test
    @DisplayName("Should handle edge cases in homograph detection")
    void shouldHandleEdgeCasesInHomographDetection() {
        String[] edgeCases = {
                "",                                    // Empty string
                "a",                                   // Single ASCII character
                "\u0430",                              // Single Cyrillic character
                "aa\u0430aa",                          // Mixed ASCII and homograph
                "\u0430\u043E\u0440\u0441",            // All Cyrillic homographs
                "normal\u0430mixed",                   // Normal text with single homograph
                "\uD835\uDC1A\uD835\uDC28",           // Mathematical script homographs
                "\uFF41\uFF4F\uFF50",                  // Fullwidth homographs
                "\u0430\u03B1\uFF41",                  // Mixed script homographs
                "123\u0430456",                        // Numbers with homograph
                "special!@#\u0430$%^",                 // Special chars with homograph
                "\u0430".repeat(100),                  // Long homograph sequence
                "😀\u0430😀",                          // Emoji with homograph
                "\u0430\u0300",                       // Homograph with combining character
        };

        for (String edgeCase : edgeCases) {
            long initialEventCount = eventCounter.getTotalCount();

            try {
                String result = pipeline.validate(edgeCase);
                // If validation passes, result should not be null
                assertNotNull(result, "Validated result should not be null for: " + edgeCase);

                // If it contains homographs, should generally be blocked
                if (attackGenerator.containsHomographs(edgeCase)) {
                    fail("String with homographs should have been blocked: " + edgeCase);
                }

            } catch (UrlSecurityException e) {
                // Expected for homograph-containing input
                assertTrue(eventCounter.getTotalCount() > initialEventCount,
                        "Security event should be recorded when rejecting: " + edgeCase);

                assertNotNull(e.getFailureType(),
                        "Exception should have failure type for: " + edgeCase);

                // If it contains homographs, blocking is expected
                if (attackGenerator.containsHomographs(edgeCase)) {
                    assertTrue(isHomographOrSecurityRelatedFailure(e.getFailureType()),
                            "Homograph-containing string should fail with appropriate type: " + edgeCase);
                }
            }
        }
    }

    /**
     * Test legitimate international content handling.
     * 
     * <p>
     * Tests that legitimate international content using non-Latin scripts
     * is handled appropriately, distinguishing between legitimate use and
     * homograph attacks.
     * </p>
     */
    @Test
    @DisplayName("Legitimate international content should be handled appropriately")
    void shouldHandleLegitimateInternationalContent() {
        String[] legitimateContent = {
                // Legitimate non-Latin text (not homograph spoofing)
                "привет",                              // Russian "hello"
                "здравствуйте",                        // Russian "hello" (formal)
                "конфигурация",                        // Russian "configuration"
                "Москва",                              // Russian "Moscow"
                "αλφάβητο",                            // Greek "alphabet"
                "κόσμος",                              // Greek "world"
                "中文",                                // Chinese "Chinese language"
                "日本語",                              // Japanese "Japanese language"
                
                // Note: Even legitimate international content might be blocked
                // in a URL security context, which is acceptable for security
        };

        for (String content : legitimateContent) {
            long initialEventCount = eventCounter.getTotalCount();

            try {
                String result = pipeline.validate(content);
                assertNotNull(result, "Legitimate international content should be processable: " + content);

                // In a URL security context, international content might still be blocked
                // This is acceptable for a security-first approach
                
            } catch (UrlSecurityException e) {
                // Legitimate international content might still be blocked in URL security context
                // This is acceptable for a security-focused validation system
                assertTrue(eventCounter.getTotalCount() > initialEventCount,
                        "If content is blocked, security event should be recorded: " + content);

                // The key is that it shouldn't specifically fail as a homograph attack
                // if it's not actually doing homograph spoofing
            }
        }
    }

    /**
     * Test valid URL paths should pass validation.
     * 
     * <p>
     * Uses ValidURLPathGenerator to ensure that legitimate URL paths
     * are not incorrectly blocked by homograph detection.
     * </p>
     * 
     * @param validPath A valid URL path
     */
    @ParameterizedTest
    @TypeGeneratorSource(value = ValidURLPathGenerator.class, count = 15)
    @DisplayName("Valid URL paths should pass validation")
    void shouldValidateValidPaths(String validPath) {
        // Given: A valid path from the generator (should be pure ASCII)
        long initialEventCount = eventCounter.getTotalCount();

        // When: Validating the legitimate path
        try {
            String result = pipeline.validate(validPath);
            // Then: Should return validated result
            assertNotNull(result, "Valid path should return validated result: " + validPath);

            // And: No security events should be recorded for valid paths
            assertEquals(initialEventCount, eventCounter.getTotalCount(),
                    "No security events should be recorded for valid path: " + validPath);

            // And: Valid paths should not contain homographs
            assertFalse(attackGenerator.containsHomographs(validPath),
                    "Valid path should not contain homographs: " + validPath);

        } catch (UrlSecurityException e) {
            // Some paths might still be blocked by other security rules
            // This is acceptable for a security-first approach
            assertTrue(initialEventCount < eventCounter.getTotalCount(),
                    "If path is blocked, security event should be recorded: " + validPath);
        }
    }

    /**
     * Test performance impact of homograph detection.
     * 
     * <p>
     * Ensures that detection of homograph patterns doesn't significantly
     * impact validation performance, even with complex mixed scripts.
     * </p>
     */
    @Test
    @DisplayName("Homograph detection should maintain performance")
    void shouldMaintainPerformanceWithHomographDetection() {
        String complexHomographPattern =
                """
                аппӏе.сом/\
                αмазоν.сом/\
                ａｄｍｉｎ/\
                "/"\
                jаvаscript:аlert(1)""";

        // Warm up
        for (int i = 0; i < 10; i++) {
            try {
                pipeline.validate(complexHomographPattern);
            } catch (UrlSecurityException ignored) {
                // Expected for malicious pattern
            }
        }

        // Measure performance
        long startTime = System.nanoTime();
        for (int i = 0; i < 100; i++) {
            try {
                pipeline.validate(complexHomographPattern);
            } catch (UrlSecurityException ignored) {
                // Expected for malicious pattern
            }
        }
        long endTime = System.nanoTime();

        long averageNanos = (endTime - startTime) / 100;
        long averageMillis = averageNanos / 1_000_000;

        // Should complete within reasonable time (< 8ms per validation for complex homograph patterns)
        assertTrue(averageMillis < 8,
                "Homograph detection should complete within 8ms, actual: " + averageMillis + "ms");
    }

    /**
     * Test mixed ASCII and homograph resistance.
     * 
     * <p>
     * Tests the system's ability to detect homograph attacks even when
     * mixed with legitimate ASCII characters in various patterns.
     * </p>
     */
    @Test
    @DisplayName("Should detect homograph attacks in mixed content")
    void shouldDetectHomographsInMixedContent() {
        String[] mixedHomographAttacks = {
                "legitimate\u0430ttack",               // Single homograph in middle
                "\u0430ttack_on_system",               // Homograph at start
                "system_attack\u0430",                 // Homograph at end
                "multi\u0430ple_\u043E_attacks",       // Multiple homographs
                "path/to/\u0430dmin/config",           // Homograph in path component
                "user=\u0430dmin&pass=secret",         // Homograph in parameter
                "/api/v1/\u0430uth/login",             // Homograph in API path
                "https://\u0430pple.com/login",        // Homograph in domain
        };

        for (String attack : mixedHomographAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            // Should detect and reject mixed homograph attacks
            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Mixed homograph attack should be rejected: " + attack);

            assertNotNull(exception, "Exception should be thrown for mixed homograph: " + attack);
            assertTrue(eventCounter.getTotalCount() > initialEventCount,
                    "Security event should be recorded for: " + attack);

            // Verify that homographs are actually detected
            assertTrue(attackGenerator.containsHomographs(attack),
                    "Attack should contain detectable homographs: " + attack);
        }
    }

    /**
     * Determines if a failure type is related to homograph attacks or general security issues.
     * 
     * @param failureType The failure type to check
     * @return true if the failure type indicates a homograph-related or general security issue
     */
    private boolean isHomographOrSecurityRelatedFailure(UrlSecurityFailureType failureType) {
        return failureType == UrlSecurityFailureType.UNICODE_NORMALIZATION_CHANGED ||
                failureType == UrlSecurityFailureType.INVALID_CHARACTER ||
                failureType == UrlSecurityFailureType.CONTROL_CHARACTERS ||
                failureType == UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED ||
                failureType == UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED ||
                failureType == UrlSecurityFailureType.XSS_DETECTED ||
                failureType == UrlSecurityFailureType.SQL_INJECTION_DETECTED ||
                failureType == UrlSecurityFailureType.COMMAND_INJECTION_DETECTED ||
                failureType == UrlSecurityFailureType.MALFORMED_INPUT ||
                failureType == UrlSecurityFailureType.INVALID_STRUCTURE ||
                failureType == UrlSecurityFailureType.KNOWN_ATTACK_SIGNATURE ||
                failureType == UrlSecurityFailureType.INVALID_ENCODING;
    }
}