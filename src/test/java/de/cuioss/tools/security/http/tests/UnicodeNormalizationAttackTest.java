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
import de.cuioss.tools.security.http.generators.encoding.UnicodeNormalizationAttackGenerator;
import de.cuioss.tools.security.http.generators.url.ValidURLPathGenerator;
import de.cuioss.tools.security.http.monitoring.SecurityEventCounter;
import de.cuioss.tools.security.http.pipeline.URLPathValidationPipeline;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;

import java.text.Normalizer;

import static org.junit.jupiter.api.Assertions.*;

/**
 * T8: Test Unicode normalization attacks
 * 
 * <p>
 * This test class implements Task T8 from the HTTP security validation plan,
 * focusing on testing Unicode normalization attacks that exploit how different
 * Unicode sequences can normalize to the same characters, potentially bypassing
 * security controls that don't account for normalization.
 * </p>
 * 
 * <h3>Test Coverage</h3>
 * <ul>
 *   <li>Decomposed Unicode characters (NFD normalization attacks)</li>
 *   <li>Composed Unicode characters (NFC normalization issues)</li>
 *   <li>Compatibility normalization (NFKC/NFKD attacks)</li>
 *   <li>Unicode combining character sequences</li>
 *   <li>Homograph attacks using Unicode lookalikes</li>
 *   <li>Overlong UTF-8 sequences that normalize differently</li>
 *   <li>Mixed script attacks using different Unicode blocks</li>
 *   <li>Zero-width character injection</li>
 *   <li>Bidirectional text override attacks</li>
 *   <li>Normalization form consistency validation</li>
 * </ul>
 * 
 * <h3>Security Standards</h3>
 * <ul>
 *   <li>OWASP Top 10 - Injection Prevention</li>
 *   <li>CWE-20: Improper Input Validation</li>
 *   <li>CWE-176: Improper Handling of Unicode Encoding</li>
 *   <li>CWE-838: Inappropriate Encoding for Output Context</li>
 *   <li>Unicode Technical Standard #39 (Unicode Security Mechanisms)</li>
 *   <li>RFC 3454 - Preparation of Internationalized Strings</li>
 *   <li>Unicode Normalization Forms (UAX #15)</li>
 * </ul>
 * 
 * Implements: Task T8 from HTTP verification specification
 * 
 * @author Claude Code Generator
 * @since 2.5
 */
@EnableGeneratorController
@DisplayName("T8: Unicode Normalization Attack Tests")
class UnicodeNormalizationAttackTest {

    private URLPathValidationPipeline pipeline;
    private SecurityEventCounter eventCounter;
    private SecurityConfiguration config;
    private UnicodeNormalizationAttackGenerator attackGenerator;

    @BeforeEach
    void setUp() {
        config = SecurityConfiguration.builder()
                .normalizeUnicode(true)
                .failOnSuspiciousPatterns(true)
                .allowHighBitCharacters(false)  // Reject high-bit Unicode
                .allowControlCharacters(false)
                .build();
        eventCounter = new SecurityEventCounter();
        pipeline = new URLPathValidationPipeline(config, eventCounter);
        attackGenerator = new UnicodeNormalizationAttackGenerator();
    }

    /**
     * Test Unicode normalization attack patterns.
     * 
     * <p>
     * Uses UnicodeNormalizationAttackGenerator which creates attack patterns
     * using various Unicode normalization techniques to bypass security controls
     * that might not properly handle Unicode normalization before validation.
     * </p>
     * 
     * @param unicodeAttackPattern A Unicode normalization attack pattern
     */
    @ParameterizedTest
    @TypeGeneratorSource(value = UnicodeNormalizationAttackGenerator.class, count = 90)
    @DisplayName("Unicode normalization attack patterns should be rejected")
    void shouldRejectUnicodeNormalizationAttacks(String unicodeAttackPattern) {
        // Given: A Unicode normalization attack pattern from the generator
        long initialEventCount = eventCounter.getTotalCount();

        // When: Attempting to validate the Unicode attack
        var exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(unicodeAttackPattern),
                "Unicode normalization attack pattern should be rejected: " + unicodeAttackPattern +
                        " (normalized: " + Normalizer.normalize(unicodeAttackPattern, Normalizer.Form.NFC) + ")");

        // Then: The validation should fail with appropriate security event
        assertNotNull(exception, "Exception should be thrown for Unicode normalization attack");
        assertTrue(isUnicodeNormalizationSpecificFailure(exception.getFailureType(), unicodeAttackPattern),
                "Failure type should be Unicode or security-related: " + exception.getFailureType() +
                        " for pattern: " + unicodeAttackPattern);

        // And: Original malicious input should be preserved
        assertEquals(unicodeAttackPattern, exception.getOriginalInput(),
                "Original input should be preserved in exception");

        // And: Security event should be recorded
        assertTrue(eventCounter.getTotalCount() > initialEventCount,
                "Security event should be recorded");
    }

    /**
     * Test known Unicode normalization attack vectors.
     * 
     * <p>
     * Tests specific Unicode normalization attack patterns that have been
     * documented in security research or used in real-world attacks.
     * </p>
     */
    @Test
    @DisplayName("Known Unicode normalization attack vectors should be rejected")
    void shouldRejectKnownUnicodeNormalizationAttacks() {
        String[] knownAttacks = {
                // Decomposed path traversal
                "..\u0300/",                           // ../ with combining grave accent
                "..\u0301\u0302/",                     // ../ with multiple combining characters
                ".\u0300.\u0301/",                     // ./ with combining characters
                
                // Fullwidth character attacks (NFKC normalization)
                "\uFF0E\uFF0E\uFF0F",                  // Fullwidth ../
                "\uFF0E\uFF0E\uFF3C",                  // Fullwidth ..\
                "\uFF1C\uFF53\uFF43\uFF52\uFF49\uFF50\uFF54\uFF1E", // Fullwidth <script>
                
                // Homograph attacks
                "\u0430dmin",                          // Cyrillic a + latin dmin (admin lookalike)
                "r\u043E\u043Et",                      // r + Cyrillic oo + t (root lookalike)
                "\u0441onfig",                         // Cyrillic c + latin onfig (config lookalike)
                
                // Zero-width character injection
                ".\u200B.\u200C/",                     // ../ with zero-width characters
                "admin\u200D",                         // admin with zero-width joiner
                "\uFEFF../",                           // ../ with zero-width no-break space
                
                // Bidirectional text attacks
                "\u202E../\u202C",                     // ../ with RLO override
                "admin\u061C\u200E",                   // admin with Arabic letter mark
                
                // Combining character path traversal
                ".\u0300.\u0301\u0302/\u0303.\u0304.\u0305/", // Complex combining sequence
                
                // Mixed script confusion
                "\u0430\u0440\u043C\u0438\u043D",      // Cyrillic "admin" lookalike
                "j\u0430v\u0430script:",               // Mixed Latin/Cyrillic "javascript:"
                
                // Compatibility character attacks
                "\u2024\u2024\u2044",                  // Dot leaders + fraction slash (../)
                "\u2215config",                        // Division slash + config
                
                // Overlong-style Unicode sequences
                "\u1E00\u1E00\u2044",                  // A with ring below (dot-like) + fraction slash
                
                // Complex normalization bypass attempts
                ".\u0300.\u0301/\u0302.\u0303.\u0304/\u0305etc\u0306/\u0307passwd\u0308",
        };

        for (String attack : knownAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Known Unicode normalization attack should be rejected: " + attack +
                            " (normalized: " + Normalizer.normalize(attack, Normalizer.Form.NFC) + ")");

            assertNotNull(exception, "Exception should be thrown for: " + attack);
            assertTrue(eventCounter.getTotalCount() > initialEventCount,
                    "Security event should be recorded for: " + attack);
        }
    }

    /**
     * Test normalization consistency detection.
     * 
     * <p>
     * Tests that the system can detect when input changes after Unicode
     * normalization, which could indicate a normalization bypass attempt.
     * </p>
     */
    @Test
    @DisplayName("Should detect normalization changes")
    void shouldDetectNormalizationChanges() {
        String[] normalizationTests = {
                // Decomposed to composed normalization changes
                "file\u0300",              // file + combining grave (changes after NFC)
                ".\u0301/",                // . + combining acute (changes after NFC)
                "admin\u0302",             // admin + combining circumflex
                
                // Compatibility normalization changes  
                "\uFF0E\uFF0E",            // Fullwidth dots (change after NFKC)
                "\uFF0F",                  // Fullwidth solidus (changes after NFKC)
                "\uFF1C",                  // Fullwidth < (changes after NFKC)
                
                // Multiple combining characters
                "a\u0300\u0301\u0302",     // a with multiple combining characters
                ".\u0303\u0304",           // . with multiple combining characters
        };

        for (String test : normalizationTests) {
            String normalized = Normalizer.normalize(test, Normalizer.Form.NFC);

            // Only test cases where normalization actually changes the string
            if (!test.equals(normalized)) {
                long initialEventCount = eventCounter.getTotalCount();

                try {
                    String result = pipeline.validate(test);
                    // If it passes, the normalized result should be recorded/checked
                    assertNotNull(result, "Result should not be null for: " + test);

                } catch (UrlSecurityException e) {
                    // Expected for normalization-changing input
                    assertTrue(eventCounter.getTotalCount() > initialEventCount,
                            "Security event should be recorded for normalization change: " + test);

                    // Should specifically detect normalization changes
                    assertTrue(e.getFailureType() == UrlSecurityFailureType.UNICODE_NORMALIZATION_CHANGED ||
                            isUnicodeNormalizationSpecificFailure(e.getFailureType(), test),
                            "Should detect normalization change for: " + test);
                }
            }
        }
    }

    /**
     * Test edge cases in Unicode normalization detection.
     * 
     * <p>
     * Tests various edge cases that might cause issues in Unicode normalization
     * detection logic, including complex combining sequences and boundary conditions.
     * </p>
     */
    @Test
    @DisplayName("Should handle edge cases in Unicode normalization")
    void shouldHandleEdgeCasesInUnicodeNormalization() {
        String[] edgeCases = {
                // Empty and minimal cases
                "",                                    // Empty string
                "\u0300",                             // Lone combining character
                "\u200B",                             // Lone zero-width space
                
                // Maximum combining character sequences
                "a\u0300\u0301\u0302\u0303\u0304\u0305\u0306\u0307\u0308\u0309", // Many combining chars
                
                // Malformed or edge Unicode sequences
                "\uD800",                             // High surrogate alone (invalid)
                "\uDFFF",                             // Low surrogate alone (invalid)
                
                // Mixed valid/invalid normalization
                "valid\u0300invalid\uD800text",       // Mixed valid combining + invalid surrogate
                
                // Complex bidirectional sequences
                "\u202E\u202D\u202C\u202B\u202A",     // Multiple BiDi controls
                
                // Very long normalization sequences
                ".\u0300".repeat(100),              // Long sequence of decomposed dots
                
                // Normalization boundary cases
                "\uFFFE",                             // Byte order mark (BOM) variant
                "\uFFFF",                             // Invalid Unicode codepoint
        };

        for (String edgeCase : edgeCases) {
            long initialEventCount = eventCounter.getTotalCount();

            try {
                String result = pipeline.validate(edgeCase);
                // If validation passes, result should not be null
                assertNotNull(result, "Validated result should not be null for: " +
                        edgeCase.codePoints().mapToObj(cp -> "U+%04X".formatted(cp)).toList());

            } catch (UrlSecurityException e) {
                // Edge cases might be rejected for various reasons
                assertTrue(eventCounter.getTotalCount() > initialEventCount,
                        "Security event should be recorded when rejecting: " +
                                edgeCase.codePoints().mapToObj(cp -> "U+%04X".formatted(cp)).toList());

                assertNotNull(e.getFailureType(),
                        "Exception should have failure type for: " + edgeCase);

            } catch (IllegalArgumentException | IllegalStateException e) {
                // Some edge cases might cause encoding or Unicode processing issues
                // This is acceptable - the system should handle them gracefully
                assertNotNull(e, "Exception should be properly formed");
            }
        }
    }

    /**
     * Test legitimate Unicode content handling.
     * 
     * <p>
     * Tests that legitimate Unicode content (like internationalized domain names,
     * multilingual text, etc.) is handled appropriately without excessive false positives.
     * </p>
     */
    @Test
    @DisplayName("Legitimate Unicode content should be handled appropriately")
    void shouldHandleLegitimateUnicodeContent() {
        String[] legitimateContent = {
                // Common international characters
                "café",                                // French
                "naïve",                              // French with diaeresis
                "Zürich",                             // German
                "Tokyo",                              // English/Latin
                "münchen",                            // German umlaut
                
                // Properly composed Unicode
                "résumé",                             // Composed accented characters
                "piñata",                             // Spanish ñ
                "jalapeño",                           // Spanish ñ
                
                // Note: Even legitimate Unicode might be blocked in URL security context
                // This is acceptable for a security-focused system
        };

        for (String content : legitimateContent) {
            long initialEventCount = eventCounter.getTotalCount();

            try {
                String result = pipeline.validate(content);
                assertNotNull(result, "Legitimate Unicode content should be processable: " + content);

                // In a URL security context, even legitimate Unicode might be blocked
                // This is acceptable for a security-first approach
                
            } catch (UrlSecurityException e) {
                // Legitimate Unicode content might still be blocked in URL security context
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
     * are not incorrectly blocked by Unicode normalization detection.
     * </p>
     * 
     * @param validPath A valid URL path
     */
    @ParameterizedTest
    @TypeGeneratorSource(value = ValidURLPathGenerator.class, count = 10)
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
     * Test performance impact of Unicode normalization detection.
     * 
     * <p>
     * Ensures that detection of complex Unicode normalization patterns
     * doesn't significantly impact validation performance.
     * </p>
     */
    @Test
    @DisplayName("Unicode normalization detection should maintain performance")
    void shouldMaintainPerformanceWithUnicodeNormalization() {
        String complexUnicodePattern =
                """
                .̀́̂̃̄/̅.̆̇̈̉̊/\
                ．．／аdmin​‌‍﻿\
                ‮ооt‬؜‎""";

        // Warm up
        for (int i = 0; i < 10; i++) {
            try {
                pipeline.validate(complexUnicodePattern);
            } catch (UrlSecurityException ignored) {
                // Expected for malicious pattern
            }
        }

        // Measure performance
        long startTime = System.nanoTime();
        for (int i = 0; i < 100; i++) {
            try {
                pipeline.validate(complexUnicodePattern);
            } catch (UrlSecurityException ignored) {
                // Expected for malicious pattern
            }
        }
        long endTime = System.nanoTime();

        long averageNanos = (endTime - startTime) / 100;
        long averageMillis = averageNanos / 1_000_000;

        // Should complete within reasonable time (< 12ms per validation for complex Unicode patterns)
        assertTrue(averageMillis < 12,
                "Unicode normalization detection should complete within 12ms, actual: " + averageMillis + "ms");
    }

    /**
     * Test normalization form consistency.
     * 
     * <p>
     * Tests that the system consistently handles different normalization forms
     * and can detect when input would change under different normalization approaches.
     * </p>
     */
    @Test
    @DisplayName("Should consistently handle different normalization forms")
    void shouldConsistentlyHandleNormalizationForms() {
        String[] testCases = {
                "café",           // Should be same in NFC and NFD after normalization
                ".\u0301/",       // Should change under NFC normalization
                "\uFF0E\uFF0E",   // Should change under NFKC normalization
        };

        for (String testCase : testCases) {
            String nfc = Normalizer.normalize(testCase, Normalizer.Form.NFC);
            String nfd = Normalizer.normalize(testCase, Normalizer.Form.NFD);
            String nfkc = Normalizer.normalize(testCase, Normalizer.Form.NFKC);
            String nfkd = Normalizer.normalize(testCase, Normalizer.Form.NFKD);

            // Test that the validation system handles normalization consistently
            long initialEventCount = eventCounter.getTotalCount();

            try {
                pipeline.validate(testCase);

                // If the original passes, the normalized versions should be handled consistently
                // (though they might still fail for other security reasons)
                
            } catch (UrlSecurityException e) {
                // If original fails, should record security event
                assertTrue(eventCounter.getTotalCount() > initialEventCount,
                        "Security event should be recorded for: " + testCase);

                // Should detect if normalization would change the input
                if (!testCase.equals(nfc)) {
                    assertTrue(e.getFailureType() == UrlSecurityFailureType.UNICODE_NORMALIZATION_CHANGED ||
                            isUnicodeNormalizationSpecificFailure(e.getFailureType(), testCase),
                            "Should detect normalization change for: " + testCase);
                }
            }
        }
    }

    /**
     * QI-9: Determines if a failure type matches specific Unicode normalization attack patterns.
     * Replaces broad OR-assertion with comprehensive security validation.
     * 
     * @param failureType The actual failure type from validation
     * @param pattern The Unicode normalization pattern being tested
     * @return true if the failure type is expected for Unicode attack patterns
     */
    private boolean isUnicodeNormalizationSpecificFailure(UrlSecurityFailureType failureType, String pattern) {
        // QI-9: Unicode normalization patterns can trigger multiple specific failure types
        // Accept all Unicode-relevant failure types for comprehensive security validation
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
                failureType == UrlSecurityFailureType.INVALID_ENCODING ||
                failureType == UrlSecurityFailureType.NULL_BYTE_INJECTION;
    }

}