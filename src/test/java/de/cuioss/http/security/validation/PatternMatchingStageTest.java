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
package de.cuioss.http.security.validation;

import de.cuioss.http.security.config.SecurityConfiguration;
import de.cuioss.http.security.core.HttpSecurityValidator;
import de.cuioss.http.security.core.UrlSecurityFailureType;
import de.cuioss.http.security.core.ValidationType;
import de.cuioss.http.security.exceptions.UrlSecurityException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive unit tests for {@link PatternMatchingStage}.
 *
 * <p>Tests cover pattern detection for various attack types including:
 * path traversal, SQL injection, XSS, command injection, and suspicious patterns.</p>
 */
class PatternMatchingStageTest {

    // ========== Basic Functionality Tests ==========

    @Test
    void shouldReturnInputWhenNoPatternMatches() {
        SecurityConfiguration config = SecurityConfiguration.defaults();
        PatternMatchingStage stage = new PatternMatchingStage(config, ValidationType.URL_PATH);

        String input = "/api/users/123";
        String result = stage.validate(input);

        assertEquals(input, result, "Pattern matching stage should return input unchanged when no patterns match");
    }

    @Test
    void shouldHandleNullInput() {
        SecurityConfiguration config = SecurityConfiguration.defaults();
        PatternMatchingStage stage = new PatternMatchingStage(config, ValidationType.URL_PATH);

        assertNull(stage.validate(null), "Pattern matching stage should return null for null input");
    }

    @Test
    void shouldHandleEmptyInput() {
        SecurityConfiguration config = SecurityConfiguration.defaults();
        PatternMatchingStage stage = new PatternMatchingStage(config, ValidationType.URL_PATH);

        assertEquals("", stage.validate(""), "Pattern matching stage should return empty string for empty input");
    }

    // ========== Path Traversal Detection Tests ==========

    @ParameterizedTest
    @ValueSource(strings = {
            "../etc/passwd",
            "..\\windows\\system32",
            "../../../root/.ssh/id_rsa",
            "/api/../../../etc/passwd",
            "....//etc/passwd",
            "....\\\\windows\\system32",
            ".%2E/etc/passwd",
            ".%2e/etc/passwd"
    })
    void shouldDetectBasicPathTraversalPatterns(String maliciousPath) {
        SecurityConfiguration config = SecurityConfiguration.defaults();
        PatternMatchingStage stage = new PatternMatchingStage(config, ValidationType.URL_PATH);

        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> stage.validate(maliciousPath));

        assertEquals(UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED, exception.getFailureType(), "Exception should indicate path traversal detection");
        assertEquals(ValidationType.URL_PATH, exception.getValidationType(), "Exception should indicate URL path validation type");
        assertEquals(maliciousPath, exception.getOriginalInput(), "Exception should preserve original malicious input");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "..%2F",
            "..%5C",
            "%2E%2E/",
            "%2e%2e/",
            "%2E%2E%2F",
            "%2e%2e%2f",
            "%2F%2E%2E",
            "%5C%2E%2E"
    })
    void shouldDetectEncodedPathTraversalPatterns(String encodedPath) {
        SecurityConfiguration config = SecurityConfiguration.defaults();
        PatternMatchingStage stage = new PatternMatchingStage(config, ValidationType.URL_PATH);

        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> stage.validate("/api" + encodedPath + "passwd"));

        assertEquals(UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED, exception.getFailureType(), "Exception should indicate path traversal detection for encoded patterns");
        assertTrue(exception.getDetail().orElse("").contains("traversal"), "Exception detail should mention traversal");
    }

    // ========== SQL Injection Detection Tests ==========

    // SQL injection tests removed - application layer responsibility

    // SQL keyword regex tests removed - application layer responsibility

    // XSS detection tests removed - application layer responsibility.
    // HTTP protocol layer focuses on URL/percent-encoding, not HTML/JS content.

    // ========== Command Injection Detection Tests ==========

    // Command injection tests removed - application layer responsibility

    // ========== Suspicious Path Pattern Tests ==========

    @ParameterizedTest
    @ValueSource(strings = {
            "/etc/passwd",
            "/proc/version",
            "/sys/devices",
            "/dev/null",
            "/boot/grub",
            "/root/.ssh",
            "\\windows\\system32\\config",
            "\\users\\administrator",
            "\\program files\\",
            "web.xml",
            "web.config",
            ".env",
            ".htaccess",
            ".htpasswd"
    })
    void shouldDetectSuspiciousPathsWithFailOnSuspiciousEnabled(String suspiciousPath) {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .failOnSuspiciousPatterns(true)
                .build();
        PatternMatchingStage stage = new PatternMatchingStage(config, ValidationType.URL_PATH);

        String fullPath = "/app" + suspiciousPath;

        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> stage.validate(fullPath));

        assertEquals(UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED, exception.getFailureType());
        assertTrue(exception.getDetail().orElse("").contains("Suspicious path"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/etc/passwd",
            "/proc/version",
            "web.xml",
            ".htaccess"
    })
    void shouldNotFailOnSuspiciousPathsWhenDisabled(String suspiciousPath) {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .failOnSuspiciousPatterns(false)
                .build();
        PatternMatchingStage stage = new PatternMatchingStage(config, ValidationType.URL_PATH);

        String fullPath = "/app" + suspiciousPath;
        String result = stage.validate(fullPath);

        assertEquals(fullPath, result); // Should pass through without throwing
    }

    // ========== Suspicious Parameter Name Tests ==========

    @ParameterizedTest
    @ValueSource(strings = {
            "script",
            "include",
            "require",
            "file",
            "path",
            "url",
            "redirect",
            "forward"
    })
    void shouldDetectSuspiciousParameterNamesWithFailOnSuspiciousEnabled(String suspiciousName) {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .failOnSuspiciousPatterns(true)
                .build();
        PatternMatchingStage stage = new PatternMatchingStage(config, ValidationType.PARAMETER_NAME);

        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> stage.validate(suspiciousName));

        assertEquals(UrlSecurityFailureType.SUSPICIOUS_PARAMETER_NAME, exception.getFailureType());
        assertEquals(ValidationType.PARAMETER_NAME, exception.getValidationType());
        assertTrue(exception.getDetail().orElse("").contains("parameter name"));
    }

    @Test
    void shouldNotFailOnSuspiciousParameterNamesWhenDisabled() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .failOnSuspiciousPatterns(false)
                .build();
        PatternMatchingStage stage = new PatternMatchingStage(config, ValidationType.PARAMETER_NAME);

        String result = stage.validate("cmd");
        assertEquals("cmd", result); // Should pass through
    }

    // ========== Case Sensitivity Tests ==========

    @Test
    void shouldDetectPatternsInCaseInsensitiveMode() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .caseSensitiveComparison(false)
                .build();
        PatternMatchingStage stage = new PatternMatchingStage(config, ValidationType.URL_PATH);

        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> stage.validate("../etc/passwd"));

        assertEquals(UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED, exception.getFailureType());
    }

    @Test
    void shouldRespectCaseSensitiveConfiguration() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .caseSensitiveComparison(true)
                .build();
        PatternMatchingStage stage = new PatternMatchingStage(config, ValidationType.URL_PATH);

        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> stage.validate("../etc/passwd"));

        assertEquals(UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED, exception.getFailureType());
    }

    // ========== Validation Type Context Tests ==========

    @Test
    void shouldApplyPathTraversalToPathsOnly() {
        SecurityConfiguration config = SecurityConfiguration.defaults();

        // Path traversal should be detected in URL_PATH
        PatternMatchingStage pathStage = new PatternMatchingStage(config, ValidationType.URL_PATH);
        assertThrows(UrlSecurityException.class, () -> pathStage.validate("../etc/passwd"));

        // Path traversal should be detected in PARAMETER_VALUE
        PatternMatchingStage paramStage = new PatternMatchingStage(config, ValidationType.PARAMETER_VALUE);
        assertThrows(UrlSecurityException.class, () -> paramStage.validate("../etc/passwd"));

        // Path traversal should be detected in PARAMETER_NAME
        PatternMatchingStage nameStage = new PatternMatchingStage(config, ValidationType.PARAMETER_NAME);
        assertThrows(UrlSecurityException.class, () -> nameStage.validate("../etc/passwd"));
    }

    // XSS validation test removed - application layer responsibility.

    @Test
    void shouldApplySuspiciousParameterNamesOnlyToParameterNames() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .failOnSuspiciousPatterns(true)
                .build();

        // Should detect in PARAMETER_NAME
        PatternMatchingStage nameStage = new PatternMatchingStage(config, ValidationType.PARAMETER_NAME);
        assertThrows(UrlSecurityException.class, () -> nameStage.validate("script"));

        // Should NOT detect in other types
        PatternMatchingStage pathStage = new PatternMatchingStage(config, ValidationType.URL_PATH);
        assertEquals("script", pathStage.validate("script"));

        PatternMatchingStage valueStage = new PatternMatchingStage(config, ValidationType.PARAMETER_VALUE);
        assertEquals("script", valueStage.validate("script"));
    }

    // ========== Conditional Validation Tests ==========

    @Test
    void shouldSupportConditionalValidation() {
        SecurityConfiguration config = SecurityConfiguration.defaults();
        PatternMatchingStage stage = new PatternMatchingStage(config, ValidationType.PARAMETER_VALUE);

        HttpSecurityValidator conditionalValidator = stage.when(input -> input != null && input.length() > 5);

        // Should pass short input without validation
        assertEquals("../", conditionalValidator.validate("../"));

        // Should validate long input and detect attack
        assertThrows(UrlSecurityException.class,
                () -> conditionalValidator.validate("../etc/passwd"));
    }

    // ========== Edge Cases ==========

    @Test
    void shouldHandleMultiplePatternMatches() {
        SecurityConfiguration config = SecurityConfiguration.defaults();
        PatternMatchingStage stage = new PatternMatchingStage(config, ValidationType.PARAMETER_VALUE);

        // Input contains both path traversal and SQL injection
        String multipleAttacks = "../passwd'; DROP TABLE users; --";

        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> stage.validate(multipleAttacks));

        // Should fail on first detected pattern (path traversal is checked first)
        assertEquals(UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED, exception.getFailureType());
    }

    @Test
    void shouldHandleVeryLongInput() {
        SecurityConfiguration config = SecurityConfiguration.defaults();
        PatternMatchingStage stage = new PatternMatchingStage(config, ValidationType.PARAMETER_VALUE);

        // Create very long input with path traversal pattern at the end
        String longInput = generateRepeatedPattern("normal", 1000) + "../etc/passwd";

        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> stage.validate(longInput));

        assertEquals(UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED, exception.getFailureType());
    }

    @Test
    void shouldHandleSpecialCharacters() {
        SecurityConfiguration config = SecurityConfiguration.defaults();
        PatternMatchingStage stage = new PatternMatchingStage(config, ValidationType.PARAMETER_VALUE);

        // Input with special characters but no attack patterns
        String specialChars = "!@#$%^&*()_+-=[]{}|;:,.<>?";
        String result = stage.validate(specialChars);

        assertEquals(specialChars, result);
    }

    // ========== toString() Test ==========

    @Test
    void shouldProvideInformativeToString() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .failOnSuspiciousPatterns(true)
                .caseSensitiveComparison(false)
                .build();
        PatternMatchingStage stage = new PatternMatchingStage(config, ValidationType.URL_PATH);

        String toString = stage.toString();

        assertTrue(toString.contains("PatternMatchingStage"));
        assertTrue(toString.contains("URL_PATH"));
        assertTrue(toString.contains("true"));
        assertTrue(toString.contains("false"));
    }

    /**
     * QI-17: Generate realistic repeated patterns instead of using .repeat().
     * Creates varied repeated patterns for pattern matching testing.
     */
    private String generateRepeatedPattern(String pattern, int count) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < count; i++) {
            result.append(pattern);
            // Add slight variation every few repetitions for realistic testing
            if (i % 20 == 19) {
                result.append(i % 10);
            }
        }
        return result.toString();
    }
}