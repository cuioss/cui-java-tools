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

import de.cuioss.tools.security.http.config.SecurityConfiguration;
import de.cuioss.tools.security.http.core.UrlSecurityFailureType;
import de.cuioss.tools.security.http.core.ValidationType;
import de.cuioss.tools.security.http.exceptions.UrlSecurityException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link DecodingStage}
 */
class DecodingStageTest {

    private SecurityConfiguration defaultConfig;
    private SecurityConfiguration strictConfig;
    private SecurityConfiguration lenientConfig;
    private DecodingStage pathDecoder;
    private DecodingStage parameterDecoder;

    @BeforeEach
    void setUp() {
        defaultConfig = SecurityConfiguration.defaults();
        strictConfig = SecurityConfiguration.strict();
        lenientConfig = SecurityConfiguration.lenient();

        pathDecoder = new DecodingStage(defaultConfig, ValidationType.URL_PATH);
        parameterDecoder = new DecodingStage(defaultConfig, ValidationType.PARAMETER_VALUE);
    }

    @Test
    @DisplayName("Should handle null input gracefully")
    void shouldHandleNullInput() {
        assertNull(pathDecoder.validate(null));
        assertNull(parameterDecoder.validate(null));
    }

    @Test
    @DisplayName("Should handle empty input")
    void shouldHandleEmptyInput() {
        assertEquals("", pathDecoder.validate(""));
        assertEquals("", parameterDecoder.validate(""));
    }

    @Test
    @DisplayName("Should decode standard URL encoding")
    void shouldDecodeStandardUrlEncoding() {
        // Basic percent encoding
        assertEquals("/api/users", pathDecoder.validate("/api/users"));
        assertEquals("/api/users/123", pathDecoder.validate("/api/users%2F123"));
        assertEquals("hello world", parameterDecoder.validate("hello%20world"));
        assertEquals("user@example.com", parameterDecoder.validate("user%40example.com"));

        // Special characters
        assertEquals("path with spaces", pathDecoder.validate("path%20with%20spaces"));
        assertEquals("query=value&other=data", parameterDecoder.validate("query%3Dvalue%26other%3Ddata"));
        assertEquals("file.txt", pathDecoder.validate("file.txt")); // No encoding needed
    }

    @Test
    @DisplayName("Should detect and block double encoding when not allowed")
    void shouldDetectDoubleEncoding() {
        // Default config doesn't allow double encoding
        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> pathDecoder.validate("/admin%252Fusers")); // %25 = encoded %
        
        assertEquals(UrlSecurityFailureType.DOUBLE_ENCODING, exception.getFailureType());
        assertEquals(ValidationType.URL_PATH, exception.getValidationType());
        assertEquals("/admin%252Fusers", exception.getOriginalInput());
        assertTrue(exception.getDetail().map(detail -> detail.contains("Double encoding pattern")).orElse(false));
    }

    @ParameterizedTest
    @DisplayName("Should detect various double encoding patterns")
    @ValueSource(strings = {
            "%252F", // %2F encoded again
            "%2525", // %25 encoded again  
            "/path%252E%252E/admin", // ../ double encoded
            "%252E%252E%252F", // ../ fully double encoded
            "file%252Etxt", // file.txt with double encoded dot
            "%2520", // space double encoded
    })
    void shouldDetectVariousDoubleEncodingPatterns(String input) {
        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> pathDecoder.validate(input));

        assertEquals(UrlSecurityFailureType.DOUBLE_ENCODING, exception.getFailureType());
        assertEquals(input, exception.getOriginalInput());
    }

    @Test
    @DisplayName("Should allow double encoding when configured")
    void shouldAllowDoubleEncodingWhenConfigured() {
        SecurityConfiguration allowingConfig = SecurityConfiguration.builder()
                .allowDoubleEncoding(true)
                .normalizeUnicode(false)
                .build();

        DecodingStage lenientDecoder = new DecodingStage(allowingConfig, ValidationType.URL_PATH);

        // This should not throw an exception
        String result = lenientDecoder.validate("/admin%252Fusers");
        assertEquals("/admin%2Fusers", result); // First layer decoded
    }

    @Test
    @DisplayName("Should detect invalid encoding sequences")
    void shouldDetectInvalidEncoding() {
        String[] invalidInputs = {
                "%Z1", // Invalid hex character
                "%1", // Incomplete encoding
                "%", // Incomplete encoding
                "%2G", // Invalid hex character
                "%%20" // Double percent without proper hex
        };

        for (String invalidInput : invalidInputs) {
            UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                    () -> pathDecoder.validate(invalidInput),
                    "Should detect invalid encoding in: " + invalidInput);

            assertEquals(UrlSecurityFailureType.INVALID_ENCODING, exception.getFailureType());
            assertEquals(invalidInput, exception.getOriginalInput());
            assertNotNull(exception.getCause());
            assertTrue(exception.getDetail().map(detail -> detail.contains("URL decoding failed")).orElse(false));
        }
    }

    @Test
    @DisplayName("Should handle Unicode normalization when enabled")
    void shouldHandleUnicodeNormalization() {
        SecurityConfiguration unicodeConfig = SecurityConfiguration.builder()
                .normalizeUnicode(true)
                .build();

        DecodingStage unicodeDecoder = new DecodingStage(unicodeConfig, ValidationType.URL_PATH);

        // String that doesn't change with normalization
        String normalInput = "regular-path";
        assertEquals(normalInput, unicodeDecoder.validate(normalInput));

        // Test with already normalized Unicode
        String normalizedUnicode = "café"; // NFC form
        assertEquals(normalizedUnicode, unicodeDecoder.validate(normalizedUnicode));
    }

    @Test
    @DisplayName("Should detect Unicode normalization changes")
    void shouldDetectUnicodeNormalizationChanges() {
        SecurityConfiguration unicodeConfig = SecurityConfiguration.builder()
                .normalizeUnicode(true)
                .build();

        DecodingStage unicodeDecoder = new DecodingStage(unicodeConfig, ValidationType.URL_PATH);

        // Create a string with decomposed Unicode that will change when normalized
        // Using combining characters that will be normalized
        String decomposed = "cafe\u0301"; // e + combining acute accent
        String composed = "café"; // precomposed character
        
        // If the input changes during normalization, it should throw an exception
        // Note: This depends on the exact Unicode composition
        if (!decomposed.equals(composed)) {
            UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                    () -> unicodeDecoder.validate(decomposed));

            assertEquals(UrlSecurityFailureType.UNICODE_NORMALIZATION_CHANGED, exception.getFailureType());
            assertEquals(decomposed, exception.getOriginalInput());
            assertEquals(Optional.of(composed), exception.getSanitizedInput());
            assertTrue(exception.getDetail().map(detail -> detail.contains("Unicode normalization changed")).orElse(false));
        }
    }

    @Test
    @DisplayName("Should skip Unicode normalization when disabled")
    void shouldSkipUnicodeNormalizationWhenDisabled() {
        SecurityConfiguration noUnicodeConfig = SecurityConfiguration.builder()
                .normalizeUnicode(false)
                .build();

        DecodingStage noUnicodeDecoder = new DecodingStage(noUnicodeConfig, ValidationType.URL_PATH);

        // Even with decomposed Unicode, should not throw exception
        String decomposed = "cafe\u0301";
        assertDoesNotThrow(() -> noUnicodeDecoder.validate(decomposed));
    }

    @Test
    @DisplayName("Should preserve validation type in exceptions")
    void shouldPreserveValidationType() {
        DecodingStage[] decoders = {
                new DecodingStage(defaultConfig, ValidationType.URL_PATH),
                new DecodingStage(defaultConfig, ValidationType.PARAMETER_NAME),
                new DecodingStage(defaultConfig, ValidationType.PARAMETER_VALUE),
                new DecodingStage(defaultConfig, ValidationType.HEADER_VALUE)
        };

        ValidationType[] expectedTypes = {
                ValidationType.URL_PATH,
                ValidationType.PARAMETER_NAME,
                ValidationType.PARAMETER_VALUE,
                ValidationType.HEADER_VALUE
        };

        for (int i = 0; i < decoders.length; i++) {
            final int index = i; // Make effectively final for lambda
            UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                    () -> decoders[index].validate("%252F"));

            assertEquals(expectedTypes[i], exception.getValidationType());
        }
    }

    @Test
    @DisplayName("Should be immutable and thread-safe")
    void shouldBeImmutableAndThreadSafe() {
        // Verify immutability via Lombok @Value annotation (check class methods are present)
        // Lombok @Value generates equals, hashCode, toString, and makes fields final
        assertDoesNotThrow(() -> DecodingStage.class.getMethod("equals", Object.class));
        assertDoesNotThrow(() -> DecodingStage.class.getMethod("hashCode"));
        assertDoesNotThrow(() -> DecodingStage.class.getMethod("toString"));

        // Test concurrent access
        DecodingStage decoder = new DecodingStage(defaultConfig, ValidationType.URL_PATH);

        // Run multiple threads concurrently
        Thread[] threads = new Thread[10];
        boolean[] results = new boolean[10];

        for (int i = 0; i < 10; i++) {
            final int threadIndex = i;
            threads[i] = new Thread(() -> {
                try {
                    String input = "/api/path%2F" + threadIndex;
                    String result = decoder.validate(input);
                    results[threadIndex] = result.equals("/api/path/" + threadIndex);
                } /*~~(Catch specific not Exception)~~>*/catch (Exception e) {
                    results[threadIndex] = false;
                }
            });
        }

        // Start all threads
        for (Thread thread : threads) {
            thread.start();
        }

        // Wait for all threads
        for (Thread thread : threads) {
            assertDoesNotThrow(() -> thread.join());
        }

        // Verify all succeeded
        for (boolean result : results) {
            assertTrue(result);
        }
    }

    @Test
    @DisplayName("Should provide meaningful toString")
    void shouldProvideMeaningfulToString() {
        String pathString = pathDecoder.toString();
        assertTrue(pathString.contains("DecodingStage"));
        assertTrue(pathString.contains("URL_PATH"));
        assertTrue(pathString.contains("allowDoubleEncoding"));
        assertTrue(pathString.contains("normalizeUnicode"));

        // Test with different config
        DecodingStage strictDecoder = new DecodingStage(strictConfig, ValidationType.PARAMETER_NAME);
        String strictString = strictDecoder.toString();
        assertTrue(strictString.contains("PARAMETER_NAME"));
    }

    @Test
    @DisplayName("Should support conditional validation")
    void shouldSupportConditionalValidation() {
        // Create conditional validator that skips null/empty
        var conditionalDecoder = pathDecoder.when(input -> input != null && !input.isEmpty());

        // Should pass through null and empty without validation
        assertNull(conditionalDecoder.validate(null));
        assertEquals("", conditionalDecoder.validate(""));

        // Should validate non-empty input
        assertEquals("/api/path", conditionalDecoder.validate("/api%2Fpath"));

        // Should still throw on double encoding for non-empty input
        assertThrows(UrlSecurityException.class,
                () -> conditionalDecoder.validate("%252F"));
    }

    /**
     * Test data provider for complex decoding scenarios
     */
    static Stream<Arguments> complexDecodingScenarios() {
        return Stream.of(
                Arguments.of("/api/users%2F123", "/api/users/123", "Basic path separator"),
                Arguments.of("name%3DJohn%26age%3D30", "name=John&age=30", "Query parameter format"),
                Arguments.of("hello%2Bworld", "hello+world", "Plus sign encoding"),
                Arguments.of("50%25%20off", "50% off", "Percent sign in text"),
                Arguments.of("file%2Etxt", "file.txt", "Dot encoding"),
                Arguments.of("path%2F..%2Fadmin", "path/../admin", "Path traversal pattern"),
                Arguments.of("%C2%A3100", "£100", "Unicode currency symbol"),
                Arguments.of("data%5B0%5D", "data[0]", "Array notation")
        );
    }

    @ParameterizedTest
    @DisplayName("Should handle complex decoding scenarios")
    @MethodSource("complexDecodingScenarios")
    void shouldHandleComplexDecodingScenarios(String input, String expected, String description) {
        String result = pathDecoder.validate(input);
        assertEquals(expected, result, description);
    }

    @Test
    @DisplayName("Should handle configuration edge cases")
    void shouldHandleConfigurationEdgeCases() {
        // Test with minimal configuration
        SecurityConfiguration minimalConfig = SecurityConfiguration.builder()
                .allowDoubleEncoding(false)
                .normalizeUnicode(false)
                .build();

        DecodingStage minimalDecoder = new DecodingStage(minimalConfig, ValidationType.URL_PATH);

        assertEquals("/api/path", minimalDecoder.validate("/api%2Fpath"));

        // Should still detect double encoding
        assertThrows(UrlSecurityException.class,
                () -> minimalDecoder.validate("%252F"));
    }

    @Test
    @DisplayName("Should handle long inputs efficiently")
    void shouldHandleLongInputsEfficiently() {
        // Create a long input with encoding
        StringBuilder longInput = new StringBuilder();
        StringBuilder expectedOutput = new StringBuilder();

        for (int i = 0; i < 1000; i++) {
            longInput.append("path%2F").append(i).append("%2F");
            expectedOutput.append("path/").append(i).append("/");
        }

        long startTime = System.nanoTime();
        String result = pathDecoder.validate(longInput.toString());
        long endTime = System.nanoTime();

        assertEquals(expectedOutput.toString(), result);

        // Should complete within reasonable time (less than 100ms for this input size)
        long durationMs = (endTime - startTime) / 1_000_000;
        assertTrue(durationMs < 100, "Decoding should be efficient, took: " + durationMs + "ms");
    }
}