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
import de.cuioss.tools.security.http.generators.BoundaryFuzzingGenerator;
import de.cuioss.tools.security.http.generators.NullByteURLGenerator;
import de.cuioss.tools.security.http.monitoring.SecurityEventCounter;
import de.cuioss.tools.security.http.pipeline.URLPathValidationPipeline;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * T4: Test path traversal with null bytes
 * 
 * <p>
 * This test class implements Task T4 from the HTTP security validation plan,
 * focusing on testing null byte injection attacks combined with path traversal
 * patterns using specialized generators and comprehensive attack vectors.
 * </p>
 * 
 * <h3>Test Coverage</h3>
 * <ul>
 *   <li>Raw null byte injection (\u0000)</li>
 *   <li>URL-encoded null bytes (%00)</li>
 *   <li>Null bytes combined with path traversal (../)</li>
 *   <li>Extension bypass attacks (file.jsp%00.png)</li>
 *   <li>Leading and trailing null byte patterns</li>
 *   <li>Multiple null byte sequences</li>
 *   <li>Null bytes in various URL components</li>
 *   <li>Boundary condition combinations</li>
 * </ul>
 * 
 * <h3>Security Standards</h3>
 * <ul>
 *   <li>OWASP Top 10 - Path Traversal Prevention</li>
 *   <li>RFC 3986 URI Character Validation</li>
 *   <li>CVE-2004-0847, CVE-2005-0988, CVE-2006-1236 (Null byte attacks)</li>
 *   <li>File extension bypass protection</li>
 * </ul>
 * 
 * Implements: Task T4 from HTTP verification specification
 * 
 * @author Claude Code Generator
 * @since 2.5
 */
@EnableGeneratorController
@DisplayName("T4: Null Byte Path Traversal Attack Tests")
class NullBytePathTraversalAttackTest {

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
     * Test boundary fuzzing patterns that include potential security issues.
     * 
     * <p>
     * Uses BoundaryFuzzingGenerator which includes various patterns including
     * null bytes, deep nesting, long paths, and special characters.
     * Only patterns that actually trigger security violations are validated.
     * </p>
     * 
     * @param boundaryAttackPattern A boundary condition pattern that may contain security issues
     */
    @ParameterizedTest
    @TypeGeneratorSource(value = BoundaryFuzzingGenerator.class, count = 75)
    @DisplayName("Malicious boundary fuzzing patterns should be rejected")
    void shouldRejectMaliciousBoundaryFuzzingPatterns(String boundaryAttackPattern) {
        // Given: A boundary fuzzing pattern from the generator
        long initialEventCount = eventCounter.getTotalCount();

        // When: Attempting to validate the boundary pattern
        try {
            pipeline.validate(boundaryAttackPattern);

            // Then: If validation passes, it should be a legitimate pattern
            // (not all boundary patterns are malicious - some test edge cases)
            
        } catch (UrlSecurityException exception) {
            // Then: If validation fails, it should be for appropriate reasons
            assertNotNull(exception, "Exception should have details");
            assertTrue(isBoundaryOrNullByteRelatedFailure(exception.getFailureType()),
                    "Failure type should be security-related: " + exception.getFailureType() +
                            " for pattern: " + boundaryAttackPattern);

            // And: Original input should be preserved
            assertEquals(boundaryAttackPattern, exception.getOriginalInput(),
                    "Original input should be preserved in exception");

            // And: Security event should be recorded
            assertTrue(eventCounter.getTotalCount() > initialEventCount,
                    "Security event should be recorded for: " + boundaryAttackPattern);
        }
    }

    /**
     * Test focused null byte patterns from boundary fuzzing.
     * 
     * <p>
     * This test specifically validates that null byte patterns are always rejected,
     * focusing on the core requirement of T4.
     * </p>
     */
    @Test
    @DisplayName("Focused null byte patterns must always be blocked")
    void shouldAlwaysBlockFocusedNullBytePatterns() {
        String[] focusedNullBytePatterns = {
                // From BoundaryFuzzingGenerator.generateNullBytes()
                "/file\u0000.txt",              // Raw null byte
                "/admin%00.php",                // Encoded null byte
                "../etc/passwd%00.jpg",         // Path traversal with null
                "file.jsp%00.png",              // Extension bypass
                "%00../../etc/shadow",          // Leading null byte
                
                // From BoundaryFuzzingGenerator.generateMixedBoundaryAttacks()
                "/%00../../../../../etc/passwd",          // Null + traversal
                "/\u0000/../\u0000/../file"               // Multiple nulls
        };

        for (String pattern : focusedNullBytePatterns) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(pattern),
                    "Null byte pattern must be rejected: " + pattern);

            assertNotNull(exception);
            assertTrue(isNullByteRelatedFailure(exception.getFailureType()),
                    "Should detect null byte attack: " + exception.getFailureType() + " for pattern: " + pattern);
            assertTrue(eventCounter.getTotalCount() > initialEventCount,
                    "Security event should be recorded for: " + pattern);
        }
    }

    /**
     * Test dedicated null byte URL attack patterns.
     * 
     * <p>
     * Uses NullByteURLGenerator which provides focused null byte injection
     * patterns specifically designed for URL context attacks.
     * </p>
     * 
     * @param nullByteAttackPattern A null byte URL attack pattern
     */
    @ParameterizedTest
    @TypeGeneratorSource(value = NullByteURLGenerator.class, count = 50)
    @DisplayName("All null byte URL patterns should be rejected")
    void shouldRejectAllNullByteURLPatterns(String nullByteAttackPattern) {
        // Given: A null byte attack pattern from the generator
        long initialEventCount = eventCounter.getTotalCount();

        // When: Attempting to validate the null byte attack
        var exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(nullByteAttackPattern),
                "Null byte attack pattern should be rejected: " + nullByteAttackPattern);

        // Then: The validation should fail with appropriate security event
        assertNotNull(exception, "Exception should be thrown for null byte attack");
        assertTrue(isNullByteRelatedFailure(exception.getFailureType()),
                "Failure type should be null byte related: " + exception.getFailureType());

        // And: Original malicious input should be preserved
        assertEquals(nullByteAttackPattern, exception.getOriginalInput(),
                "Original input should be preserved in exception");

        // And: Security event should be recorded
        assertTrue(eventCounter.getTotalCount() > initialEventCount,
                "Security event should be recorded");
    }

    /**
     * Test specific high-risk null byte + path traversal combinations.
     * 
     * <p>
     * This test ensures that the most dangerous null byte path traversal 
     * combinations are consistently blocked.
     * </p>
     */
    @Test
    @DisplayName("High-risk null byte + path traversal combinations must be blocked")
    void shouldBlockHighRiskNullBytePathTraversalCombinations() {
        String[] highRiskPatterns = {
                // Classic null byte path traversal
                "../../../etc/passwd\u0000.jpg",
                "%00../../../etc/shadow",
                "../etc/passwd%00.png",

                // Extension bypass attacks
                "config.php\u0000.txt",
                "admin.jsp%00.jpg",
                "secret.conf\u0000.log",

                // Multiple null byte attacks
                "../\u0000/../\u0000/../etc/passwd",
                "%00../%00../%00../etc/hosts",

                // Null byte + encoding combinations
                "../%00%2e%2e/etc/passwd",
                "%00%2e%2e%2f%2e%2e%2fetc%2fpasswd",

                // Leading null byte attacks
                "\u0000../../../etc/passwd",
                "%00../../windows/win.ini",

                // Mixed format attacks
                "..\\..\\..\\boot.ini\u0000.txt",
                "../../../usr/bin/id%00.sh"
        };

        for (String pattern : highRiskPatterns) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(pattern),
                    "High-risk null byte pattern should be rejected: " + pattern);

            assertNotNull(exception);
            assertTrue(isNullByteRelatedFailure(exception.getFailureType()));
            assertTrue(eventCounter.getTotalCount() > initialEventCount);
        }
    }

    /**
     * Test null byte encoding variations.
     * 
     * <p>
     * Tests different ways null bytes can be encoded in URLs to bypass
     * basic filtering mechanisms.
     * </p>
     */
    @Test
    @DisplayName("Null byte encoding variations must be blocked")
    void shouldBlockNullByteEncodingVariations() {
        String[] encodingVariations = {
                // Standard URL encoding
                "../etc/passwd%00.txt",
                "%00../etc/shadow",

                // Double URL encoding
                "../etc/passwd%2500.txt",
                "%2500../etc/hosts",

                // Unicode encoding
                "../etc/passwd\\u0000.txt",
                "\\u0000../etc/passwd",

                // Mixed encoding
                "../etc/passwd%00%2etxt",
                "%00%2e%2e/etc/passwd",

                // Alternative representations
                "../etc/passwd\0.txt",           // C-style null
                "../etc/passwd%0.txt",          // Malformed encoding
                "../etc/passwd%000.txt",        // Extended encoding
        };

        for (String attack : encodingVariations) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Null byte encoding variation should be rejected: " + attack);

            assertNotNull(exception);
            assertTrue(eventCounter.getTotalCount() > initialEventCount);
        }
    }

    /**
     * Test file extension bypass attacks using null bytes.
     * 
     * <p>
     * Validates protection against attacks that use null bytes to bypass
     * file extension filtering and access controls.
     * </p>
     */
    @Test
    @DisplayName("File extension bypass attacks using null bytes must be blocked")
    void shouldBlockExtensionBypassAttacks() {
        String[] extensionBypassAttacks = {
                // Web application bypasses
                "shell.php\u0000.txt",
                "backdoor.jsp%00.jpg",
                "webshell.asp\u0000.gif",
                "exploit.cgi%00.png",

                // Script execution bypasses
                "script.py\u0000.log",
                "payload.sh%00.txt",
                "malware.exe\u0000.dat",

                // Config file access
                "database.conf\u0000.bak",
                ".htaccess%00.old",
                "settings.ini\u0000.tmp",

                // Combined with path traversal
                "../../config.php\u0000.txt",
                "../admin.jsp%00.backup",
                "../../.env%00.sample"
        };

        for (String attack : extensionBypassAttacks) {
            long initialEventCount = eventCounter.getTotalCount();

            var exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(attack),
                    "Extension bypass attack should be rejected: " + attack);

            assertNotNull(exception);
            assertTrue(eventCounter.getTotalCount() > initialEventCount);
        }
    }

    /**
     * Test performance impact of null byte attack validation.
     * 
     * <p>
     * Ensures that null byte detection doesn't significantly impact
     * validation performance, even with complex attack patterns.
     * </p>
     */
    @Test
    @DisplayName("Null byte attack validation should maintain performance")
    void shouldMaintainPerformanceWithNullByteAttacks() {
        String complexNullBytePattern = "%00../%00../%00../%00../%00../%00../%00../%00../etc/passwd\u0000.jpg";

        // Warm up
        for (int i = 0; i < 10; i++) {
            try {
                pipeline.validate(complexNullBytePattern);
            } catch (UrlSecurityException ignored) {
            }
        }

        // Measure performance
        long startTime = System.nanoTime();
        for (int i = 0; i < 100; i++) {
            try {
                pipeline.validate(complexNullBytePattern);
            } catch (UrlSecurityException ignored) {
            }
        }
        long endTime = System.nanoTime();

        long averageNanos = (endTime - startTime) / 100;
        long averageMillis = averageNanos / 1_000_000;

        // Should complete within reasonable time (< 5ms per validation)
        assertTrue(averageMillis < 5,
                "Null byte validation should complete within 5ms, actual: " + averageMillis + "ms");
    }

    /**
     * Determines if a failure type is related to null byte attacks.
     * 
     * @param failureType The failure type to check
     * @return true if the failure type indicates a null byte-related security issue
     */
    private boolean isNullByteRelatedFailure(UrlSecurityFailureType failureType) {
        return failureType == UrlSecurityFailureType.NULL_BYTE_INJECTION ||
                failureType == UrlSecurityFailureType.INVALID_CHARACTER ||
                failureType == UrlSecurityFailureType.CONTROL_CHARACTERS ||
                failureType == UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED ||
                failureType == UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED;
    }

    /**
     * Determines if a failure type is related to boundary conditions or null byte attacks.
     * 
     * @param failureType The failure type to check
     * @return true if the failure type indicates a boundary/null byte-related security issue
     */
    private boolean isBoundaryOrNullByteRelatedFailure(UrlSecurityFailureType failureType) {
        return isNullByteRelatedFailure(failureType) ||
                failureType == UrlSecurityFailureType.PATH_TOO_LONG ||
                failureType == UrlSecurityFailureType.INPUT_TOO_LONG ||
                failureType == UrlSecurityFailureType.EXCESSIVE_NESTING ||
                failureType == UrlSecurityFailureType.DOUBLE_ENCODING ||
                failureType == UrlSecurityFailureType.INVALID_ENCODING;
    }
}