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
import de.cuioss.tools.security.http.generators.UnicodeControlCharacterAttackGenerator;
import de.cuioss.tools.security.http.monitoring.SecurityEventCounter;
import de.cuioss.tools.security.http.pipeline.URLPathValidationPipeline;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * T10: Test Unicode control character attacks
 * 
 * <p>
 * This test class implements Task T10 from the HTTP security validation plan,
 * focusing on testing Unicode control character injection attacks that can
 * bypass security filters, manipulate text processing, or cause parsing issues.
 * Control characters are non-printing characters that can have significant
 * security implications when not properly handled.
 * </p>
 * 
 * <h3>Test Coverage</h3>
 * <ul>
 *   <li>C0 Control Characters (0x00-0x1F) injection</li>
 *   <li>C1 Control Characters (0x80-0x9F) injection</li>
 *   <li>Format Control Characters (Line/Paragraph separators)</li>
 *   <li>Bidirectional Control Characters (LTR/RTL overrides)</li>
 *   <li>Zero-Width Characters (ZWSP, ZWNJ, ZWJ, ZWNBSP)</li>
 *   <li>Variation Selectors and Combining Marks</li>
 *   <li>Private Use Area Characters</li>
 *   <li>Invalid Surrogate Pairs</li>
 *   <li>Line Breaking Control Characters</li>
 *   <li>URL Context Control Character Injection</li>
 *   <li>Mixed Control Character Sequences</li>
 *   <li>Encoded Control Character Bypasses</li>
 * </ul>
 * 
 * <h3>Security Standards</h3>
 * <ul>
 *   <li>CWE-74: Improper Neutralization of Special Elements</li>
 *   <li>CWE-20: Improper Input Validation</li>
 *   <li>CWE-176: Improper Handling of Unicode Encoding</li>
 *   <li>OWASP Top 10 - Injection Prevention</li>
 *   <li>Unicode Technical Standard #39 (Security Mechanisms)</li>
 *   <li>RFC 3629 - UTF-8 Character Encoding</li>
 * </ul>
 * 
 * Implements: Task T10 from HTTP verification specification
 * 
 * @author Claude Code Generator
 * @since 2.5
 */
@EnableGeneratorController
@DisplayName("T10: Unicode Control Character Attack Tests")
class UnicodeControlCharacterAttackTest {

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
     * Test comprehensive Unicode control character attack patterns.
     * 
     * <p>
     * Uses UnicodeControlCharacterAttackGenerator which creates 12 different
     * types of control character attacks that should be detected and blocked
     * by the security pipeline.
     * </p>
     * 
     * @param controlCharacterAttackPattern A Unicode control character attack pattern
     */
    @ParameterizedTest
    @TypeGeneratorSource(value = UnicodeControlCharacterAttackGenerator.class, count = 120)
    @DisplayName("All Unicode control character attacks should be rejected")
    void shouldRejectAllUnicodeControlCharacterAttacks(String controlCharacterAttackPattern) {
        // Given: A control character attack pattern from the generator
        long initialEventCount = eventCounter.getTotalCount();

        // When: Attempting to validate the control character attack
        var exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(controlCharacterAttackPattern),
                "Control character attack should be rejected: " + getDisplayableString(controlCharacterAttackPattern));

        // Then: The validation should fail with appropriate security event
        assertNotNull(exception, "Exception should be thrown for control character attack");
        assertTrue(isControlCharacterRelatedFailure(exception.getFailureType()),
                "Failure type should be control character related: " + exception.getFailureType() +
                        " for pattern: " + getDisplayableString(controlCharacterAttackPattern));

        // And: Original malicious input should be preserved
        assertEquals(controlCharacterAttackPattern, exception.getOriginalInput(),
                "Original input should be preserved in exception");

        // And: Security event should be recorded
        assertTrue(eventCounter.getTotalCount() > initialEventCount,
                "Security event should be recorded for: " + getDisplayableString(controlCharacterAttackPattern));
    }

    /**
     * Test specific C0 control character attacks (0x00-0x1F).
     * 
     * <p>
     * These are ASCII control characters that can cause significant
     * security issues when injected into URLs or file paths.
     * </p>
     */
    @Test
    @DisplayName("C0 control character attacks must be blocked")
    void shouldBlockC0ControlCharacterAttacks() {
        String[] c0ControlAttacks = {
                // Null byte attacks
                "/etc/passwd\u0000.txt",
                "../config\u0000.backup",

                // Backspace manipulation
                "admin\u0008\u0008\u0008guest",
                "/secure\u0008\u0008\u0008public/data",

                // Tab injection
                "../\u0009/etc/passwd",
                "config\u0009=\u0009../../../etc/shadow",

                // Line feed/carriage return injection
                "/path\n../etc/passwd",
                "/data\r\n../config",

                // Escape sequence injection
                "\u001B[2J../etc/passwd",
                "/clear\u001B[H\u001B[J../config",

                // Unit separator manipulation
                "data\u001F../etc/passwd",
                "/files\u001F\u001F../config"
        };

        for (String attack : c0ControlAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "C0 control attack should be rejected: " + getDisplayableString(attack));

            assertNotNull(exception);
            assertTrue(isControlCharacterRelatedFailure(exception.getFailureType()),
                    "Should detect C0 control character: " + exception.getFailureType() +
                            " for: " + getDisplayableString(attack));
            assertTrue(eventCounter.getTotalCount() > initialEventCount);
        }
    }

    /**
     * Test C1 control character attacks (0x80-0x9F).
     * 
     * <p>
     * Extended ASCII control characters that are often overlooked
     * by security filters but can cause parsing issues.
     * </p>
     */
    @Test
    @DisplayName("C1 control character attacks must be blocked")
    void shouldBlockC1ControlCharacterAttacks() {
        String[] c1ControlAttacks = {
                // Padding character attacks
                "../etc/passwd\u0080",
                "/config\u0080\u0080../admin",

                // High Octet Preset attacks
                "\u0081../etc/shadow",
                "/data\u0081bypass\u0081../config",

                // Reverse line feed attacks
                "/path\u008D../etc/passwd",
                "config\u008D\u008D../admin",

                // Device Control String attacks
                "\u0090../etc/passwd\u009C",
                "/secure\u0090malicious\u009C../config",

                // String Terminator attacks
                "data\u009C../etc/passwd",
                "/files\u009C\u009C../admin",

                // Application Program Command attacks
                "\u009F../etc/shadow",
                "/backup\u009F../config\u009F"
        };

        for (String attack : c1ControlAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "C1 control attack should be rejected: " + getDisplayableString(attack));

            assertNotNull(exception);
            assertTrue(eventCounter.getTotalCount() > initialEventCount);
        }
    }

    /**
     * Test bidirectional control character attacks.
     * 
     * <p>
     * Tests attacks using BiDi override characters that can manipulate
     * text display direction to deceive users or bypass filters.
     * </p>
     */
    @Test
    @DisplayName("Bidirectional control character attacks must be blocked")
    void shouldBlockBidirectionalControlAttacks() {
        String[] bidiAttacks = {
                // Right-to-Left Override attacks
                "\u202E../etc/passwd\u202C",
                "/data\u202Epasswd.cte/\u202C",

                // Left-to-Right Override attacks
                "\u202D../etc/passwd\u202C",
                "/files\u202Dconfig../\u202C",

                // Mixed BiDi marks
                "../\u200E\u200Fetc/passwd",
                "/admin\u200F\u200E../config",

                // Arabic Letter Mark injection
                "data\u061C../etc/passwd",
                "/secure\u061C\u061C../config",

                // Complex BiDi manipulation
                "\u202E\u061C../etc/passwd\u200F\u202C",
                "/path\u202D\u200E../config\u061C\u202C"
        };

        for (String attack : bidiAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "BiDi control attack should be rejected: " + getDisplayableString(attack));

            assertNotNull(exception);
            assertTrue(eventCounter.getTotalCount() > initialEventCount);
        }
    }

    /**
     * Test zero-width character injection attacks.
     * 
     * <p>
     * These invisible characters can be used to bypass string matching
     * and hide malicious content within seemingly innocent URLs.
     * </p>
     */
    @Test
    @DisplayName("Zero-width character injection attacks must be blocked")
    void shouldBlockZeroWidthCharacterAttacks() {
        String[] zeroWidthAttacks = {
                // Zero Width Space injection
                "../\u200Betc/\u200Bpasswd",
                "/ad\u200Bmin/../con\u200Bfig",

                // Zero Width Non-Joiner injection
                "../\u200Cetc\u200C/passwd",
                "/se\u200Ccure/../\u200Cconfig",

                // Zero Width Joiner injection
                "etc\u200D/\u200Dpasswd",
                "/da\u200Dta/../ad\u200Dmin",

                // Zero Width No-Break Space (BOM)
                "\uFEFF../etc/passwd",
                "/files\uFEFF/../\uFEFFconfig",

                // Mongolian Vowel Separator
                "../\u180Eetc/passwd",
                "/admin\u180E/../config",

                // Mixed zero-width characters
                "..\u200B/\u200C\u200Detc\uFEFF/passwd",
                "/sec\u200Bure\u200C/../con\u200Dfig\uFEFF"
        };

        for (String attack : zeroWidthAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Zero-width attack should be rejected: " + getDisplayableString(attack));

            assertNotNull(exception);
            assertTrue(eventCounter.getTotalCount() > initialEventCount);
        }
    }

    /**
     * Test format control character attacks.
     * 
     * <p>
     * Characters that control text formatting and layout, which can
     * be exploited to manipulate parsing or bypass security checks.
     * </p>
     */
    @Test
    @DisplayName("Format control character attacks must be blocked")
    void shouldBlockFormatControlAttacks() {
        String[] formatControlAttacks = {
                // Line Separator attacks
                "../etc\u2028/passwd",
                "/admin\u2028/../config",

                // Paragraph Separator attacks
                "../\u2029etc/passwd",
                "/data\u2029/../admin",

                // Non-Breaking Space attacks
                "../etc\u00A0/passwd",
                "/secure\u00A0/../config",

                // Ogham Space Mark attacks
                "../\u1680etc/passwd",
                "/files\u1680/../admin",

                // Mixed format control
                "..\u2028/\u2029etc\u00A0/passwd",
                "/da\u2028ta\u2029/../con\u00A0fig"
        };

        for (String attack : formatControlAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Format control attack should be rejected: " + getDisplayableString(attack));

            assertNotNull(exception);
            assertTrue(eventCounter.getTotalCount() > initialEventCount);
        }
    }

    /**
     * Test private use area character attacks.
     * 
     * <p>
     * Private use characters have undefined behavior and can be used
     * to bypass filters or cause unexpected parsing behavior.
     * </p>
     */
    @Test
    @DisplayName("Private use area character attacks must be blocked")
    void shouldBlockPrivateUseAreaAttacks() {
        String[] privateUseAttacks = {
                // Basic private use area
                "../etc\uE000/passwd",
                "/admin\uE001/../config",

                // Apple logo character (common private use)
                "../etc\uF8FF/passwd",
                "/data\uF8FF/../admin",

                // Other private use ranges
                "../\uF000etc/passwd",
                "/secure\uE100/../config",

                // CJK compatibility (edge case)
                "../etc\uF900/passwd",
                "/files\uF900/../admin",

                // Mixed private use characters
                "..\uE000/\uF8FFetc\uF000/passwd",
                "/ad\uE001min\uE100/../con\uF900fig"
        };

        for (String attack : privateUseAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Private use area attack should be rejected: " + getDisplayableString(attack));

            assertNotNull(exception);
            assertTrue(eventCounter.getTotalCount() > initialEventCount);
        }
    }

    /**
     * Test invalid surrogate pair attacks.
     * 
     * <p>
     * Invalid UTF-16 surrogate sequences that can cause parsing errors
     * or unexpected behavior in Unicode processing systems.
     * </p>
     */
    @Test
    @DisplayName("Invalid surrogate pair attacks must be blocked")
    void shouldBlockInvalidSurrogatePairAttacks() {
        String[] surrogateAttacks = {
                // Invalid high surrogate without low
                "../etc\uD800/passwd",
                "/admin\uD800/../config",

                // Invalid low surrogate without high
                "../\uDC00etc/passwd",
                "/data\uDC00/../admin",

                // Reversed surrogate pair
                "../etc\uDC00\uD800/passwd",
                "/files\uDC00\uD800/../config",

                // Multiple invalid surrogates
                "..\uD800/\uDC00\uD800etc/passwd",
                "/se\uDC00cure\uD800/../admin"
        };

        for (String attack : surrogateAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Surrogate pair attack should be rejected: " + getDisplayableString(attack));

            assertNotNull(exception);
            assertTrue(eventCounter.getTotalCount() > initialEventCount);
        }
    }

    /**
     * Test URL-encoded control character bypass attempts.
     * 
     * <p>
     * Attackers often encode control characters to bypass basic filters
     * that only check for literal control characters.
     * </p>
     */
    @Test
    @DisplayName("URL-encoded control character bypasses must be blocked")
    void shouldBlockUrlEncodedControlCharacterBypasses() {
        String[] encodedAttacks = {
                // URL-encoded null bytes
                "../etc/passwd%00.txt",
                "/admin%00/../config",

                // URL-encoded line feeds
                "../etc%0A/passwd",
                "/data%0D%0A../admin",

                // URL-encoded escape sequences
                "../etc%1B/passwd",
                "/secure%1B/../config",

                // UTF-8 encoded C1 controls
                "../etc%C2%80/passwd",
                "/admin%C2%81/../config",

                // Double-encoded controls
                "../etc%2500/passwd",
                "/data%250A../admin",

                // Mixed encoding
                "../etc%00passwd%0A.txt",
                "/admin%1B%C2%80../config"
        };

        for (String attack : encodedAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Encoded control attack should be rejected: " + attack);

            assertNotNull(exception);
            assertTrue(eventCounter.getTotalCount() > initialEventCount);
        }
    }

    /**
     * Test performance impact of control character attack validation.
     * 
     * <p>
     * Ensures that control character detection doesn't significantly
     * impact validation performance, even with complex patterns.
     * </p>
     */
    @Test
    @DisplayName("Control character attack validation should maintain performance")
    void shouldMaintainPerformanceWithControlCharacterAttacks() {
        String complexControlPattern = "\u202E\u0000..\u200B/\u0080\u2028etc\uE000/\u200Cpasswd\uD800\u202C";

        // Warm up
        for (int i = 0; i < 10; i++) {
            try {
                pipeline.validate(complexControlPattern);
            } catch (UrlSecurityException ignored) {
            }
        }

        // Measure performance
        long startTime = System.nanoTime();
        for (int i = 0; i < 100; i++) {
            try {
                pipeline.validate(complexControlPattern);
            } catch (UrlSecurityException ignored) {
            }
        }
        long endTime = System.nanoTime();

        long averageNanos = (endTime - startTime) / 100;
        long averageMillis = averageNanos / 1_000_000;

        // Should complete within reasonable time (< 6ms per validation)
        assertTrue(averageMillis < 6,
                "Control character validation should complete within 6ms, actual: " + averageMillis + "ms");
    }

    /**
     * Test control character detection capabilities.
     * 
     * <p>
     * Verifies that the generator's control character detection
     * methods work correctly for validation purposes.
     * </p>
     */
    @Test
    @DisplayName("Control character detection should work correctly")
    void shouldDetectControlCharactersCorrectly() {
        UnicodeControlCharacterAttackGenerator generator = new UnicodeControlCharacterAttackGenerator();

        // Should detect control characters
        assertTrue(generator.containsControlCharacters("test\u0000string"));
        assertTrue(generator.containsControlCharacters("\u0080test"));
        assertTrue(generator.containsControlCharacters("test\u200Bstring"));
        assertTrue(generator.containsControlCharacters("\u202Etest\u202C"));

        // Should not detect in clean strings
        assertFalse(generator.containsControlCharacters("clean/path/file.txt"));
        assertFalse(generator.containsControlCharacters("admin/config"));
        assertFalse(generator.containsControlCharacters(null));
        assertFalse(generator.containsControlCharacters(""));
    }

    /**
     * Determines if a failure type is related to control character attacks.
     * 
     * @param failureType The failure type to check
     * @return true if the failure type indicates a control character-related security issue
     */
    private boolean isControlCharacterRelatedFailure(UrlSecurityFailureType failureType) {
        return failureType == UrlSecurityFailureType.CONTROL_CHARACTERS ||
                failureType == UrlSecurityFailureType.INVALID_CHARACTER ||
                failureType == UrlSecurityFailureType.NULL_BYTE_INJECTION ||
                failureType == UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED ||
                failureType == UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED ||
                failureType == UrlSecurityFailureType.INVALID_ENCODING;
    }

    /**
     * Convert a string with control characters to a displayable format for debugging.
     * 
     * @param input The string that may contain control characters
     * @return A displayable representation showing control characters as Unicode escapes
     */
    private String getDisplayableString(String input) {
        if (input == null) {
            return "null";
        }

        StringBuilder result = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (Character.isISOControl(c) || c >= 0x80 && c <= 0x9F ||
                    c == '\u200B' || c == '\u200C' || c == '\u200D' || c == '\uFEFF') {
                result.append("\\u%04X".formatted((int) c));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }
}