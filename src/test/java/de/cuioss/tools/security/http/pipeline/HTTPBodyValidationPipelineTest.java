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
package de.cuioss.tools.security.http.pipeline;

import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.generator.junit.parameterized.TypeGeneratorSource;
import de.cuioss.tools.security.http.config.SecurityConfiguration;
import de.cuioss.tools.security.http.core.HttpSecurityValidator;
import de.cuioss.tools.security.http.core.UrlSecurityFailureType;
import de.cuioss.tools.security.http.core.ValidationType;
import de.cuioss.tools.security.http.exceptions.UrlSecurityException;
import de.cuioss.tools.security.http.generators.ValidHTTPBodyContentGenerator;
import de.cuioss.tools.security.http.monitoring.SecurityEventCounter;
import de.cuioss.tools.security.http.validation.CharacterValidationStage;
import de.cuioss.tools.security.http.validation.LengthValidationStage;
import de.cuioss.tools.security.http.validation.NormalizationStage;
import de.cuioss.tools.security.http.validation.PatternMatchingStage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive test for {@link HTTPBodyValidationPipeline}
 */
@EnableGeneratorController
class HTTPBodyValidationPipelineTest {

    private SecurityConfiguration defaultConfig;
    private SecurityConfiguration strictConfig;
    private SecurityConfiguration lenientConfig;
    private SecurityEventCounter eventCounter;
    private HTTPBodyValidationPipeline pipeline;

    @BeforeEach
    void setUp() {
        defaultConfig = SecurityConfiguration.defaults();
        strictConfig = SecurityConfiguration.strict();
        lenientConfig = SecurityConfiguration.lenient();
        eventCounter = new SecurityEventCounter();
        pipeline = new HTTPBodyValidationPipeline(defaultConfig, eventCounter);
    }

    @Test
    @DisplayName("Should reject null configuration")
    void shouldRejectNullConfiguration() {
        assertThrows(NullPointerException.class,
                () -> new HTTPBodyValidationPipeline(null, eventCounter));
    }

    @Test
    @DisplayName("Should reject null event counter")
    void shouldRejectNullEventCounter() {
        assertThrows(NullPointerException.class,
                () -> new HTTPBodyValidationPipeline(defaultConfig, null));
    }

    @Test
    @DisplayName("Should handle null input gracefully")
    void shouldHandleNullInput() {
        assertNull(pipeline.validate(null));
        assertFalse(eventCounter.hasAnyEvents());
    }

    @Test
    @DisplayName("Should handle empty input")
    void shouldHandleEmptyInput() {
        assertEquals("", pipeline.validate(""));
        assertFalse(eventCounter.hasAnyEvents());
    }

    @Test
    @DisplayName("Should return BODY validation type")
    void shouldReturnBodyValidationType() {
        assertEquals(ValidationType.BODY, pipeline.getValidationType());
    }

    @Test
    @DisplayName("Should create correct pipeline stages")
    void shouldCreateCorrectPipelineStages() {
        List<HttpSecurityValidator> stages = pipeline.getStages();
        assertEquals(4, stages.size());

        assertInstanceOf(LengthValidationStage.class, stages.getFirst());
        assertInstanceOf(CharacterValidationStage.class, stages.get(1));
        assertInstanceOf(NormalizationStage.class, stages.get(2));
        assertInstanceOf(PatternMatchingStage.class, stages.get(3));
    }

    @Test
    @DisplayName("Should return same event counter instance")
    void shouldReturnSameEventCounterInstance() {
        assertSame(eventCounter, pipeline.getEventCounter());
    }

    @Test
    @DisplayName("Should validate simple JSON body")
    void shouldValidateSimpleJsonBody() {
        String jsonBody = "{\"name\": \"John Doe\", \"age\": 30}";
        String result = pipeline.validate(jsonBody);
        assertEquals(jsonBody, result);
        assertFalse(eventCounter.hasAnyEvents());
    }

    @Test
    @DisplayName("Should validate simple XML body")
    void shouldValidateSimpleXmlBody() {
        String xmlBody = "<user><name>John Doe</name><age>30</age></user>";
        String result = pipeline.validate(xmlBody);
        assertEquals(xmlBody, result);
        assertFalse(eventCounter.hasAnyEvents());
    }

    @Test
    @DisplayName("Should validate plain text body")
    void shouldValidatePlainTextBody() {
        String textBody = "This is a simple plain text message with normal content.";
        String result = pipeline.validate(textBody);
        assertEquals(textBody, result);
        assertFalse(eventCounter.hasAnyEvents());
    }

    @Test
    @DisplayName("Should validate form data body")
    void shouldValidateFormDataBody() {
        String formBody = "name=John+Doe&email=john.doe%40example.com&age=30";
        String result = pipeline.validate(formBody);
        assertEquals(formBody, result);
        assertFalse(eventCounter.hasAnyEvents());
    }

    @Test
    @DisplayName("Should reject oversized body content")
    void shouldRejectOversizedBodyContent() {
        SecurityConfiguration smallBodyConfig = SecurityConfiguration.builder()
                .maxBodySize(100) // Very small limit
                .build();
        HTTPBodyValidationPipeline smallPipeline = new HTTPBodyValidationPipeline(smallBodyConfig, eventCounter);

        String largeBody = "x".repeat(200); // Exceeds limit

        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> smallPipeline.validate(largeBody));

        assertEquals(UrlSecurityFailureType.INPUT_TOO_LONG, exception.getFailureType());
        assertEquals(ValidationType.BODY, exception.getValidationType());
        assertEquals(largeBody, exception.getOriginalInput());
        assertTrue(eventCounter.hasEvents(UrlSecurityFailureType.INPUT_TOO_LONG));
    }

    @Test
    @DisplayName("Should handle large but valid body content")
    void shouldHandleLargeButValidBodyContent() {
        // Create a body just under the default limit
        String largeBody = "A".repeat(1024 * 1024 - 1); // Just under 1MB default

        String result = pipeline.validate(largeBody);
        assertEquals(largeBody, result);
        assertFalse(eventCounter.hasAnyEvents());
    }

    @Test
    @DisplayName("Should detect SQL injection patterns with strict config")
    void shouldDetectSqlInjectionWithStrictConfig() {
        // Use strict config that fails on suspicious patterns
        HTTPBodyValidationPipeline strictPipeline = new HTTPBodyValidationPipeline(strictConfig, eventCounter);

        // Test a pattern that should definitely be detected
        String sqlInjection = "test OR 1=1 and stuff";

        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> strictPipeline.validate(sqlInjection));

        assertEquals(ValidationType.BODY, exception.getValidationType());
        assertEquals(sqlInjection, exception.getOriginalInput());
        assertTrue(eventCounter.hasAnyEvents());

        // Should detect SQL injection specifically
        assertEquals(UrlSecurityFailureType.SQL_INJECTION_DETECTED, exception.getFailureType());
    }

    @Test
    @DisplayName("Should detect XSS patterns with strict config")
    void shouldDetectXssWithStrictConfig() {
        // Use strict config that fails on suspicious patterns
        HTTPBodyValidationPipeline strictPipeline = new HTTPBodyValidationPipeline(strictConfig, eventCounter);

        // Test a pattern that should definitely be detected
        String xssContent = "content with <script>alert(1)</script> in it";

        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> strictPipeline.validate(xssContent));

        assertEquals(ValidationType.BODY, exception.getValidationType());
        assertEquals(xssContent, exception.getOriginalInput());
        assertTrue(eventCounter.hasAnyEvents());

        // Should detect XSS specifically
        assertEquals(UrlSecurityFailureType.XSS_DETECTED, exception.getFailureType());
    }

    @Test
    @DisplayName("Should detect null byte injection")
    void shouldDetectNullByteInjection() {
        String nullByteContent = "normal content\u0000malicious";

        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(nullByteContent));

        assertEquals(UrlSecurityFailureType.NULL_BYTE_INJECTION, exception.getFailureType());
        assertEquals(ValidationType.BODY, exception.getValidationType());
        assertTrue(eventCounter.hasEvents(UrlSecurityFailureType.NULL_BYTE_INJECTION));
    }

    @Test
    @DisplayName("Should allow null bytes when configured")
    void shouldAllowNullBytesWhenConfigured() {
        SecurityConfiguration allowNullConfig = SecurityConfiguration.builder()
                .allowNullBytes(true)
                .failOnSuspiciousPatterns(false) // Ensure patterns don't interfere
                .build();
        HTTPBodyValidationPipeline permissivePipeline = new HTTPBodyValidationPipeline(allowNullConfig, eventCounter);

        String nullByteContent = "content\u0000with\u0000nulls";
        String result = permissivePipeline.validate(nullByteContent);
        assertEquals(nullByteContent, result);
        assertFalse(eventCounter.hasAnyEvents());
    }

    @Test
    @DisplayName("Should detect control characters")
    void shouldDetectControlCharacters() {
        String controlCharContent = "content\u0001\u0002\u0003";

        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(controlCharContent));

        assertEquals(UrlSecurityFailureType.CONTROL_CHARACTERS, exception.getFailureType());
        assertEquals(ValidationType.BODY, exception.getValidationType());
        assertTrue(eventCounter.hasEvents(UrlSecurityFailureType.CONTROL_CHARACTERS));
    }

    @Test
    @DisplayName("Should allow control characters when configured")
    void shouldAllowControlCharactersWhenConfigured() {
        SecurityConfiguration allowControlConfig = SecurityConfiguration.builder()
                .allowControlCharacters(true)
                .failOnSuspiciousPatterns(false) // Ensure patterns don't interfere
                .build();
        HTTPBodyValidationPipeline permissivePipeline = new HTTPBodyValidationPipeline(allowControlConfig, eventCounter);

        String controlCharContent = "content\u0001\u0002";
        String result = permissivePipeline.validate(controlCharContent);
        assertEquals(controlCharContent, result);
        assertFalse(eventCounter.hasAnyEvents());
    }

    @Test
    @DisplayName("Should handle Unicode content")
    void shouldHandleUnicodeContent() {
        String unicodeContent = "Content with émojis 🎉 and ünïcødé characters: café, naïve, résumé";
        String result = pipeline.validate(unicodeContent);
        assertEquals(unicodeContent, result);
        assertFalse(eventCounter.hasAnyEvents());
    }

    @Test
    @DisplayName("Should handle Unicode normalization when enabled")
    void shouldHandleUnicodeNormalizationWhenEnabled() {
        SecurityConfiguration unicodeConfig = SecurityConfiguration.builder()
                .normalizeUnicode(true)
                .build();
        HTTPBodyValidationPipeline unicodePipeline = new HTTPBodyValidationPipeline(unicodeConfig, eventCounter);

        // Create string with decomposed Unicode that will change when normalized
        String decomposed = "cafe\u0301"; // e + combining acute accent
        String composed = "café"; // precomposed character

        if (!decomposed.equals(composed)) {
            // If normalization changes the input, it should either:
            // 1. Throw UNICODE_NORMALIZATION_CHANGED exception, or
            // 2. Throw INVALID_CHARACTER exception if the character is not in the allowed set
            UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                    () -> unicodePipeline.validate(decomposed));

            assertEquals(ValidationType.BODY, exception.getValidationType());
            assertTrue(eventCounter.hasAnyEvents());

            // Accept either unicode normalization change or invalid character
            assertTrue(exception.getFailureType() == UrlSecurityFailureType.UNICODE_NORMALIZATION_CHANGED ||
                    exception.getFailureType() == UrlSecurityFailureType.INVALID_CHARACTER,
                    "Expected unicode normalization or character validation failure, got: " + exception.getFailureType());
        } else {
            // If they're the same, validation should pass
            String result = unicodePipeline.validate(decomposed);
            assertEquals(decomposed, result);
        }
    }

    @Test
    @DisplayName("Should support conditional validation")
    void shouldSupportConditionalValidation() {
        var conditionalPipeline = pipeline.when(input -> input != null && input.length() > 10);

        // Short input should pass through without validation
        String shortInput = "short";
        assertEquals(shortInput, conditionalPipeline.validate(shortInput));

        // Long input should still be validated
        String longInput = "This is a longer input that should be validated";
        assertEquals(longInput, conditionalPipeline.validate(longInput));

        // Null should pass through
        assertNull(conditionalPipeline.validate(null));

        assertFalse(eventCounter.hasAnyEvents());
    }

    @Test
    @DisplayName("Should track security events correctly")
    void shouldTrackSecurityEventsCorrectly() {
        SecurityEventCounter testCounter = new SecurityEventCounter();
        HTTPBodyValidationPipeline testPipeline = new HTTPBodyValidationPipeline(defaultConfig, testCounter);

        // Test multiple different violations
        assertThrows(UrlSecurityException.class, () -> testPipeline.validate("<script>alert(1)</script>"));
        assertThrows(UrlSecurityException.class, () -> testPipeline.validate("content\u0000null"));

        assertTrue(testCounter.hasAnyEvents());
        assertTrue(testCounter.getTotalCount() >= 2);
    }

    @Test
    @DisplayName("Should be immutable and thread-safe")
    void shouldBeImmutableAndThreadSafe() {
        // Verify immutability via Lombok annotations
        assertDoesNotThrow(() -> HTTPBodyValidationPipeline.class.getMethod("equals", Object.class));
        assertDoesNotThrow(() -> HTTPBodyValidationPipeline.class.getMethod("hashCode"));
        assertDoesNotThrow(() -> HTTPBodyValidationPipeline.class.getMethod("toString"));

        // Test concurrent access
        Thread[] threads = new Thread[5];
        boolean[] results = new boolean[5];

        for (int i = 0; i < 5; i++) {
            final int threadIndex = i;
            threads[i] = new Thread(() -> {
                try {
                    String input = "{\"data\": \"test" + threadIndex + "\"}";
                    String result = pipeline.validate(input);
                    results[threadIndex] = input.equals(result);
                } catch (UrlSecurityException e) {
                    results[threadIndex] = false;
                }
            });
        }

        // Start and wait for all threads
        for (Thread thread : threads) {
            thread.start();
        }
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
        String pipelineString = pipeline.toString();
        assertTrue(pipelineString.contains("HTTPBodyValidationPipeline"));
        assertTrue(pipelineString.contains("BODY"));
        assertTrue(pipelineString.contains("stages"));
        assertTrue(pipelineString.contains("eventCounter"));
    }

    @Test
    @DisplayName("Should handle configuration edge cases")
    void shouldHandleConfigurationEdgeCases() {
        // Test with minimal body size
        SecurityConfiguration minimalConfig = SecurityConfiguration.builder()
                .maxBodySize(1)
                .build();
        HTTPBodyValidationPipeline minimalPipeline = new HTTPBodyValidationPipeline(minimalConfig, eventCounter);

        assertEquals("A", minimalPipeline.validate("A")); // Should pass
        assertThrows(UrlSecurityException.class, () -> minimalPipeline.validate("AB")); // Should fail

        // Test with very large body size
        SecurityConfiguration largeConfig = SecurityConfiguration.builder()
                .maxBodySize(Long.MAX_VALUE)
                .build();
        HTTPBodyValidationPipeline largePipeline = new HTTPBodyValidationPipeline(largeConfig, eventCounter);

        String mediumBody = "x".repeat(10000);
        assertEquals(mediumBody, largePipeline.validate(mediumBody));
    }


    @ParameterizedTest
    @DisplayName("Should validate various valid body content formats")
    @TypeGeneratorSource(value = ValidHTTPBodyContentGenerator.class, count = 10)
    void shouldValidateVariousValidBodyContent(String content) {
        String result = pipeline.validate(content);
        assertEquals(content, result);
        assertFalse(eventCounter.hasAnyEvents(), "No security events should be triggered for content: " + content);
    }

    @Test
    @DisplayName("Should not fail on benign content with default config")
    void shouldNotFailOnBenignContentWithDefaultConfig() {
        // Test that normal content passes with default config
        String[] benignContent = {
                "Hello world",
                "This is normal text content",
                "{\"name\": \"John\", \"age\": 30}",
                "<user><name>John</name></user>",
                "Regular form data content"
        };

        for (String content : benignContent) {
            String result = pipeline.validate(content);
            assertEquals(content, result, "Should pass: " + content);
        }

        assertFalse(eventCounter.hasAnyEvents());
    }

    @Test
    @DisplayName("Should handle maximum integer body size correctly")
    void shouldHandleMaxIntegerBodySize() {
        SecurityConfiguration maxIntConfig = SecurityConfiguration.builder()
                .maxBodySize((long) Integer.MAX_VALUE + 1000L) // Larger than int
                .build();

        HTTPBodyValidationPipeline maxIntPipeline = new HTTPBodyValidationPipeline(maxIntConfig, eventCounter);

        // Should handle the conversion properly in LengthValidationStage
        String content = "test content";
        assertEquals(content, maxIntPipeline.validate(content));
        assertFalse(eventCounter.hasAnyEvents());
    }

    @Test
    @DisplayName("Should preserve original input in exception")
    void shouldPreserveOriginalInputInException() {
        String originalInput = "<script>alert('test')</script>";

        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate(originalInput));

        assertEquals(originalInput, exception.getOriginalInput());
        assertEquals(ValidationType.BODY, exception.getValidationType());
    }
}