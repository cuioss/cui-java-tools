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
package de.cuioss.tools.security.http.validation;

import de.cuioss.test.generator.Generators;
import de.cuioss.tools.security.http.config.SecurityConfiguration;
import de.cuioss.tools.security.http.core.HttpSecurityValidator;
import de.cuioss.tools.security.http.core.UrlSecurityFailureType;
import de.cuioss.tools.security.http.core.ValidationType;
import de.cuioss.tools.security.http.exceptions.UrlSecurityException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive unit tests for {@link LengthValidationStage}.
 * 
 * <p>Tests cover length validation for all HTTP component types with various
 * configuration scenarios and edge cases.</p>
 */
class LengthValidationStageTest {

    // ========== Basic Functionality Tests ==========

    @Test
    void shouldReturnInputWhenWithinLimits() {
        SecurityConfiguration config = SecurityConfiguration.defaults();
        LengthValidationStage stage = new LengthValidationStage(config, ValidationType.URL_PATH);

        String input = "/api/users/123";
        String result = stage.validate(input);

        assertEquals(input, result);
    }

    @Test
    void shouldHandleNullInput() {
        SecurityConfiguration config = SecurityConfiguration.defaults();
        LengthValidationStage stage = new LengthValidationStage(config, ValidationType.URL_PATH);

        assertNull(stage.validate(null));
    }

    @Test
    void shouldHandleEmptyInput() {
        SecurityConfiguration config = SecurityConfiguration.defaults();
        LengthValidationStage stage = new LengthValidationStage(config, ValidationType.URL_PATH);

        assertEquals("", stage.validate(""));
    }

    @Test
    void shouldPassExactlyAtLimit() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .maxPathLength(10)
                .build();
        LengthValidationStage stage = new LengthValidationStage(config, ValidationType.URL_PATH);

        String input = "1234567890"; // exactly 10 characters
        String result = stage.validate(input);

        assertEquals(input, result);
    }

    // ========== URL Path Length Tests ==========

    @Test
    void shouldFailWhenPathTooLong() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .maxPathLength(10)
                .build();
        LengthValidationStage stage = new LengthValidationStage(config, ValidationType.URL_PATH);

        String longPath = "12345678901"; // 11 characters, exceeds limit of 10

        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> stage.validate(longPath));

        assertEquals(UrlSecurityFailureType.PATH_TOO_LONG, exception.getFailureType());
        assertEquals(ValidationType.URL_PATH, exception.getValidationType());
        assertEquals(longPath, exception.getOriginalInput());
        assertTrue(exception.getDetail().orElse("").contains("URL path length 11 exceeds maximum 10"));
    }

    @Test
    void shouldUseDefaultPathLength() {
        SecurityConfiguration config = SecurityConfiguration.defaults();
        LengthValidationStage stage = new LengthValidationStage(config, ValidationType.URL_PATH);

        // Should pass with reasonable path length
        String reasonablePath = "/api/users/123/profile";
        assertEquals(reasonablePath, stage.validate(reasonablePath));

        // Should fail with path over default limit (4096)
        String extremelyLongPath = Generators.letterStrings(4100, 4150).next(); // Just over default limit
        assertThrows(UrlSecurityException.class, () -> stage.validate(extremelyLongPath));
    }

    // ========== Parameter Name Length Tests ==========

    @Test
    void shouldFailWhenParameterNameTooLong() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .maxParameterNameLength(20)
                .build();
        LengthValidationStage stage = new LengthValidationStage(config, ValidationType.PARAMETER_NAME);

        String longParamName = "very_long_parameter_name_that_exceeds_limit"; // > 20 chars

        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> stage.validate(longParamName));

        assertEquals(UrlSecurityFailureType.INPUT_TOO_LONG, exception.getFailureType());
        assertEquals(ValidationType.PARAMETER_NAME, exception.getValidationType());
        assertTrue(exception.getDetail().orElse("").contains("Parameter name"));
        assertTrue(exception.getDetail().orElse("").contains("exceeds maximum 20"));
    }

    @Test
    void shouldPassValidParameterName() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .maxParameterNameLength(20)
                .build();
        LengthValidationStage stage = new LengthValidationStage(config, ValidationType.PARAMETER_NAME);

        String validParamName = "userId"; // Well within limit
        assertEquals(validParamName, stage.validate(validParamName));
    }

    // ========== Parameter Value Length Tests ==========

    @Test
    void shouldFailWhenParameterValueTooLong() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .maxParameterValueLength(50)
                .build();
        LengthValidationStage stage = new LengthValidationStage(config, ValidationType.PARAMETER_VALUE);

        String longParamValue = generateTestString(51); // QI-17: Exceeds limit of 50

        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> stage.validate(longParamValue));

        assertEquals(UrlSecurityFailureType.INPUT_TOO_LONG, exception.getFailureType());
        assertEquals(ValidationType.PARAMETER_VALUE, exception.getValidationType());
        assertTrue(exception.getDetail().isPresent());
        String detail = exception.getDetail().get();
        assertTrue(detail.contains("Parameter value"));
        assertTrue(detail.contains("51 exceeds maximum 50"));
    }

    // ========== Header Name Length Tests ==========

    @Test
    void shouldFailWhenHeaderNameTooLong() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .maxHeaderNameLength(30)
                .build();
        LengthValidationStage stage = new LengthValidationStage(config, ValidationType.HEADER_NAME);

        String longHeaderName = "Very-Long-Custom-Header-Name-That-Exceeds-Limit"; // > 30 chars

        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> stage.validate(longHeaderName));

        assertEquals(UrlSecurityFailureType.INPUT_TOO_LONG, exception.getFailureType());
        assertEquals(ValidationType.HEADER_NAME, exception.getValidationType());
        assertTrue(exception.getDetail().orElse("").contains("Header name"));
    }

    @Test
    void shouldPassValidHeaderName() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .maxHeaderNameLength(30)
                .build();
        LengthValidationStage stage = new LengthValidationStage(config, ValidationType.HEADER_NAME);

        String validHeaderName = "Authorization"; // Well within limit
        assertEquals(validHeaderName, stage.validate(validHeaderName));
    }

    // ========== Header Value Length Tests ==========

    @Test
    void shouldFailWhenHeaderValueTooLong() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .maxHeaderValueLength(100)
                .build();
        LengthValidationStage stage = new LengthValidationStage(config, ValidationType.HEADER_VALUE);

        String longHeaderValue = "Bearer " + Generators.letterStrings(95, 100).next(); // Just over 100 chars total

        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> stage.validate(longHeaderValue));

        assertEquals(UrlSecurityFailureType.INPUT_TOO_LONG, exception.getFailureType());
        assertEquals(ValidationType.HEADER_VALUE, exception.getValidationType());
        assertTrue(exception.getDetail().orElse("").contains("Header value"));
    }

    // ========== Cookie Name Length Tests ==========

    @Test
    void shouldFailWhenCookieNameTooLong() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .maxCookieNameLength(15)
                .build();
        LengthValidationStage stage = new LengthValidationStage(config, ValidationType.COOKIE_NAME);

        String longCookieName = "very_long_cookie_name_exceeds_limit"; // > 15 chars

        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> stage.validate(longCookieName));

        assertEquals(UrlSecurityFailureType.INPUT_TOO_LONG, exception.getFailureType());
        assertEquals(ValidationType.COOKIE_NAME, exception.getValidationType());
        assertTrue(exception.getDetail().orElse("").contains("Cookie name"));
    }

    @Test
    void shouldPassValidCookieName() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .maxCookieNameLength(15)
                .build();
        LengthValidationStage stage = new LengthValidationStage(config, ValidationType.COOKIE_NAME);

        String validCookieName = "JSESSIONID"; // Well within limit
        assertEquals(validCookieName, stage.validate(validCookieName));
    }

    // ========== Cookie Value Length Tests ==========

    @Test
    void shouldFailWhenCookieValueTooLong() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .maxCookieValueLength(200)
                .build();
        LengthValidationStage stage = new LengthValidationStage(config, ValidationType.COOKIE_VALUE);

        String longCookieValue = generateTestString(201); // QI-17: Exceeds limit of 200

        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> stage.validate(longCookieValue));

        assertEquals(UrlSecurityFailureType.INPUT_TOO_LONG, exception.getFailureType());
        assertEquals(ValidationType.COOKIE_VALUE, exception.getValidationType());
        assertTrue(exception.getDetail().orElse("").contains("Cookie value"));
    }

    // ========== Body Size Length Tests ==========

    @Test
    void shouldFailWhenBodyTooLong() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .maxBodySize(1000) // 1000 bytes
                .build();
        LengthValidationStage stage = new LengthValidationStage(config, ValidationType.BODY);

        String longBody = generateTestString(1001); // QI-17: Exceeds limit of 1000

        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> stage.validate(longBody));

        assertEquals(UrlSecurityFailureType.INPUT_TOO_LONG, exception.getFailureType());
        assertEquals(ValidationType.BODY, exception.getValidationType());
        assertTrue(exception.getDetail().isPresent());
        String detail = exception.getDetail().get();
        assertTrue(detail.contains("Request body"));
        assertTrue(detail.contains("1001 exceeds maximum 1000"));
    }

    @Test
    void shouldPassValidBodySize() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .maxBodySize(1000)
                .build();
        LengthValidationStage stage = new LengthValidationStage(config, ValidationType.BODY);

        String validBody = Generators.letterStrings(450, 500).next(); // Well within limit
        assertEquals(validBody, stage.validate(validBody));
    }

    @Test
    void shouldHandleLargeBodySizeLimit() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .maxBodySize(Long.MAX_VALUE) // Very large limit
                .build();
        LengthValidationStage stage = new LengthValidationStage(config, ValidationType.BODY);

        // Should use Integer.MAX_VALUE as the effective limit for string length
        String reasonableBody = Generators.letterStrings(950, 1000).next();
        assertEquals(reasonableBody, stage.validate(reasonableBody));
    }

    // ========== All Validation Types Test ==========

    @ParameterizedTest
    @EnumSource(ValidationType.class)
    void shouldHandleAllValidationTypes(ValidationType validationType) {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .maxPathLength(100)
                .maxParameterNameLength(50)
                .maxParameterValueLength(200)
                .maxHeaderNameLength(75)
                .maxHeaderValueLength(300)
                .maxCookieNameLength(60)
                .maxCookieValueLength(250)
                .maxBodySize(500)
                .build();

        LengthValidationStage stage = new LengthValidationStage(config, validationType);

        // Test valid input for each type
        String validInput = "valid_input";
        String result = stage.validate(validInput);
        assertEquals(validInput, result);

        // Test input that exceeds all limits
        String veryLongInput = Generators.letterStrings(1005, 1050).next(); // Exceeds all configured limits
        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> stage.validate(veryLongInput));

        // Verify correct failure type based on validation type
        if (validationType == ValidationType.URL_PATH) {
            assertEquals(UrlSecurityFailureType.PATH_TOO_LONG, exception.getFailureType());
        } else {
            assertEquals(UrlSecurityFailureType.INPUT_TOO_LONG, exception.getFailureType());
        }
        assertEquals(validationType, exception.getValidationType());
    }

    // ========== Edge Cases ==========

    @Test
    void shouldHandleMinimalLengthLimits() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .maxParameterNameLength(1) // Minimal limit - only single characters allowed
                .build();
        LengthValidationStage stage = new LengthValidationStage(config, ValidationType.PARAMETER_NAME);

        // Empty string should pass
        assertEquals("", stage.validate(""));

        // Single character should pass
        assertEquals("a", stage.validate("a"));

        // Multiple characters should fail
        assertThrows(UrlSecurityException.class, () -> stage.validate("ab"));
    }

    @Test
    void shouldHandleUnicodeCharacters() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .maxParameterValueLength(10)
                .build();
        LengthValidationStage stage = new LengthValidationStage(config, ValidationType.PARAMETER_VALUE);

        // Unicode characters like accented letters count as single characters  
        String unicodeString = "café"; // 4 characters including é
        assertEquals(unicodeString, stage.validate(unicodeString));

        // Note: Emojis may count as multiple characters in Java string length
        String basicString = "test"; // 4 characters, well within limit
        assertEquals(basicString, stage.validate(basicString));

        // Exceeding limit with regular characters
        String longString = "12345678901"; // 11 characters, exceeds limit of 10
        assertThrows(UrlSecurityException.class, () -> stage.validate(longString));
    }

    @Test
    void shouldHandleSpecialCharacters() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .maxParameterValueLength(10)
                .build();
        LengthValidationStage stage = new LengthValidationStage(config, ValidationType.PARAMETER_VALUE);

        // Special characters should be counted normally
        String specialChars = "!@#$%^&*()"; // 10 characters, at limit
        assertEquals(specialChars, stage.validate(specialChars));

        // Exceeding with special characters
        String tooManySpecialChars = "!@#$%^&*()~"; // 11 characters, exceeds limit
        assertThrows(UrlSecurityException.class, () -> stage.validate(tooManySpecialChars));
    }

    // ========== Configuration Integration Tests ==========

    @Test
    void shouldUseStrictConfiguration() {
        SecurityConfiguration config = SecurityConfiguration.strict();
        LengthValidationStage stage = new LengthValidationStage(config, ValidationType.URL_PATH);

        // Should use strict limits (maxPathLength = 1024 in strict config)
        String longPath = generateTestString(1025); // QI-17: Exceeds strict limit
        assertThrows(UrlSecurityException.class, () -> stage.validate(longPath));

        String validPath = Generators.letterStrings(450, 500).next(); // Within strict limit
        assertEquals(validPath, stage.validate(validPath));
    }

    @Test
    void shouldUseLenientConfiguration() {
        SecurityConfiguration config = SecurityConfiguration.lenient();
        LengthValidationStage stage = new LengthValidationStage(config, ValidationType.URL_PATH);

        // Should use lenient limits (maxPathLength = 8192 in lenient config)
        String longPath = Generators.letterStrings(7000, 7500).next(); // Within lenient limit
        assertEquals(longPath, stage.validate(longPath));

        String veryLongPath = Generators.letterStrings(8200, 8250).next(); // Just over lenient limit
        assertThrows(UrlSecurityException.class, () -> stage.validate(veryLongPath));
    }

    @Test
    void shouldUseDefaultConfiguration() {
        SecurityConfiguration config = SecurityConfiguration.defaults();
        LengthValidationStage stage = new LengthValidationStage(config, ValidationType.URL_PATH);

        // Should use default limits (maxPathLength = 4096 in default config)
        String longPath = Generators.letterStrings(3500, 3800).next(); // Within default limit
        assertEquals(longPath, stage.validate(longPath));

        String veryLongPath = Generators.letterStrings(4100, 4150).next(); // Just over default limit
        assertThrows(UrlSecurityException.class, () -> stage.validate(veryLongPath));
    }

    // ========== Conditional Validation Tests ==========

    @Test
    void shouldSupportConditionalValidation() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .maxParameterValueLength(10)
                .build();
        LengthValidationStage stage = new LengthValidationStage(config, ValidationType.PARAMETER_VALUE);

        HttpSecurityValidator conditionalValidator = stage.when(input -> input != null && input.startsWith("validate_"));

        // Should pass input that doesn't match condition without validation
        String longInputNoPrefix = "this_is_a_very_long_parameter_value"; // > 10 chars but no prefix
        assertEquals(longInputNoPrefix, conditionalValidator.validate(longInputNoPrefix));

        // Should validate input that matches condition
        String longInputWithPrefix = "validate_this_long_value"; // > 10 chars with prefix
        assertThrows(UrlSecurityException.class,
                () -> conditionalValidator.validate(longInputWithPrefix));

        // Should pass valid input with condition
        String validInputWithPrefix = "validate_"; // Within limit with prefix (exactly 9 chars)
        assertEquals(validInputWithPrefix, conditionalValidator.validate(validInputWithPrefix));
    }

    // ========== toString() Test ==========

    @Test
    void shouldProvideInformativeToString() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .maxPathLength(2048)
                .build();
        LengthValidationStage stage = new LengthValidationStage(config, ValidationType.URL_PATH);

        String toString = stage.toString();

        assertTrue(toString.contains("LengthValidationStage"));
        assertTrue(toString.contains("URL_PATH"));
        assertTrue(toString.contains("2048"));
    }

    @Test
    void shouldShowCorrectLimitsInToString() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .maxParameterValueLength(512)
                .build();
        LengthValidationStage stage = new LengthValidationStage(config, ValidationType.PARAMETER_VALUE);

        String toString = stage.toString();

        assertTrue(toString.contains("PARAMETER_VALUE"));
        assertTrue(toString.contains("512"));
    }

    // ========== Performance Edge Cases ==========

    @Test
    void shouldHandleVeryLongStringEfficiently() {
        SecurityConfiguration config = SecurityConfiguration.builder()
                .maxParameterValueLength(1000000) // 1 million characters
                .build();
        LengthValidationStage stage = new LengthValidationStage(config, ValidationType.PARAMETER_VALUE);

        // Should efficiently handle very long strings within limit
        String veryLongString = Generators.letterStrings(400000, 500000).next(); // Replaces .repeat(500000) - massive pattern
        long startTime = System.nanoTime();
        String result = stage.validate(veryLongString);
        long endTime = System.nanoTime();

        assertEquals(veryLongString, result);
        // Validation should be very fast (O(1)) - just length check
        long durationMs = (endTime - startTime) / 1_000_000;
        assertTrue(durationMs < 100, "Length validation should be very fast, took: " + durationMs + "ms");
    }

    /**
     * QI-17: Generate realistic test strings instead of using .repeat().
     * QI-14/QI-10: Creates varied content for length validation boundary testing.
     * Replaced hardcoded char array with dynamic generation for better maintainability.
     */
    private String generateTestString(int length) {
        StringBuilder result = new StringBuilder();

        // QI-14: Use algorithmic character generation instead of hardcoded array
        for (int i = 0; i < length; i++) {
            char c = (char) ('a' + (i % 26)); // Generate a-z cyclically
            result.append(c);
        }
        return result.toString();
    }
}