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

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.generator.junit.parameterized.TypeGeneratorSource;
import de.cuioss.tools.security.http.config.SecurityConfiguration;
import de.cuioss.tools.security.http.core.HttpSecurityValidator;
import de.cuioss.tools.security.http.core.UrlSecurityFailureType;
import de.cuioss.tools.security.http.core.ValidationType;
import de.cuioss.tools.security.http.exceptions.UrlSecurityException;
import de.cuioss.tools.security.http.generators.body.ValidHTTPBodyContentGenerator;
import de.cuioss.tools.security.http.monitoring.SecurityEventCounter;
import de.cuioss.tools.security.http.validation.CharacterValidationStage;
import de.cuioss.tools.security.http.validation.LengthValidationStage;
import de.cuioss.tools.security.http.validation.NormalizationStage;
import de.cuioss.tools.security.http.validation.PatternMatchingStage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

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

    @Nested
    class PipelineCreation {

        @Test
        void shouldRejectNullConfiguration() {
            assertThrows(NullPointerException.class,
                    () -> new HTTPBodyValidationPipeline(null, eventCounter));
        }

        @Test
        void shouldRejectNullEventCounter() {
            assertThrows(NullPointerException.class,
                    () -> new HTTPBodyValidationPipeline(defaultConfig, null));
        }

        @Test
        void shouldReturnBodyValidationType() {
            assertEquals(ValidationType.BODY, pipeline.getValidationType());
        }

        @Test
        void shouldCreateCorrectPipelineStages() {
            List<HttpSecurityValidator> stages = pipeline.getStages();
            assertEquals(4, stages.size());

            assertInstanceOf(LengthValidationStage.class, stages.getFirst());
            assertInstanceOf(CharacterValidationStage.class, stages.get(1));
            assertInstanceOf(NormalizationStage.class, stages.get(2));
            assertInstanceOf(PatternMatchingStage.class, stages.get(3));
        }

        @Test
        void shouldReturnSameEventCounterInstance() {
            assertSame(eventCounter, pipeline.getEventCounter());
        }
    }

    @Nested
    class ValidInputHandling {

        @Test
        void shouldHandleNullInput() {
            assertNull(pipeline.validate(null));
            assertFalse(eventCounter.hasAnyEvents());
        }

        @Test
        void shouldHandleEmptyInput() {
            assertEquals("", pipeline.validate(""));
            assertFalse(eventCounter.hasAnyEvents());
        }

        @ParameterizedTest
        @TypeGeneratorSource(value = ValidHTTPBodyContentGenerator.class, count = 10)
        void shouldValidateVariousValidBodyContent(String content) {
            String result = pipeline.validate(content);
            assertEquals(content, result);
            assertFalse(eventCounter.hasAnyEvents());
        }

        @ParameterizedTest
        @TypeGeneratorSource(value = ValidHTTPBodyContentGenerator.class, count = 10)
        void shouldValidateBodyVariations(String bodyContent) throws UrlSecurityException {
            String result = pipeline.validate(bodyContent);
            assertNotNull(result);
            assertEquals(bodyContent, result);
        }
    }

    @Nested
    class SecurityValidation {

        @Test
        void shouldRejectNullByteInjection() {
            String nullByteContent = "content with null byte\u0000here";
            UrlSecurityException exception = assertThrows(UrlSecurityException.class, () ->
                    pipeline.validate(nullByteContent));
            assertEquals(UrlSecurityFailureType.NULL_BYTE_INJECTION, exception.getFailureType());
        }

        @Test
        void shouldRejectOversizedContent() {
            String oversizedContent = generateBodyContent((int) (defaultConfig.maxBodySize() + 1000));
            UrlSecurityException exception = assertThrows(UrlSecurityException.class, () ->
                    pipeline.validate(oversizedContent));
            assertEquals(UrlSecurityFailureType.INPUT_TOO_LONG, exception.getFailureType());
        }

        @Test
        void shouldRejectOversizedBodyContent() {
            SecurityConfiguration smallBodyConfig = SecurityConfiguration.builder()
                    .maxBodySize(100)
                    .build();
            HTTPBodyValidationPipeline smallPipeline = new HTTPBodyValidationPipeline(smallBodyConfig, eventCounter);

            String largeBody = generateBodyContent(200);

            UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                    () -> smallPipeline.validate(largeBody));

            assertEquals(UrlSecurityFailureType.INPUT_TOO_LONG, exception.getFailureType());
            assertEquals(ValidationType.BODY, exception.getValidationType());
            assertEquals(largeBody, exception.getOriginalInput());
        }

        @Test
        void shouldHandleLargeButValidBodyContent() {
            String largeBody = generateBodyContent(1024 * 1024 - 1);

            String result = pipeline.validate(largeBody);
            assertEquals(largeBody, result);
            assertFalse(eventCounter.hasAnyEvents());
        }

        @Test
        void shouldDetectNullByteInjection() {
            String nullByteContent = "normal content\u0000malicious";

            UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(nullByteContent));

            assertEquals(UrlSecurityFailureType.NULL_BYTE_INJECTION, exception.getFailureType());
            assertEquals(ValidationType.BODY, exception.getValidationType());
        }

        @Test
        void shouldDetectControlCharacters() {
            String controlCharContent = "content\u0001\u0002\u0003";

            UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(controlCharContent));

            assertEquals(UrlSecurityFailureType.CONTROL_CHARACTERS, exception.getFailureType());
            assertEquals(ValidationType.BODY, exception.getValidationType());
        }

        @Test
        void shouldDetectSqlInjectionWithStrictConfig() {
            HTTPBodyValidationPipeline strictPipeline = new HTTPBodyValidationPipeline(strictConfig, eventCounter);

            String sqlInjection = "test OR 1=1 and stuff";

            UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                    () -> strictPipeline.validate(sqlInjection));

            assertEquals(ValidationType.BODY, exception.getValidationType());
            assertEquals(sqlInjection, exception.getOriginalInput());
            assertEquals(UrlSecurityFailureType.SQL_INJECTION_DETECTED, exception.getFailureType());
        }

        @Test
        void shouldDetectXssWithStrictConfig() {
            HTTPBodyValidationPipeline strictPipeline = new HTTPBodyValidationPipeline(strictConfig, eventCounter);

            String xssContent = "content with <script>alert(1)</script> in it";

            UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                    () -> strictPipeline.validate(xssContent));

            assertEquals(ValidationType.BODY, exception.getValidationType());
            assertEquals(xssContent, exception.getOriginalInput());
            assertEquals(UrlSecurityFailureType.XSS_DETECTED, exception.getFailureType());
        }
    }

    @Nested
    class ConfigurationSpecific {

        @Test
        void shouldAllowNullBytesWhenConfigured() {
            SecurityConfiguration allowNullConfig = SecurityConfiguration.builder()
                    .allowNullBytes(true)
                    .failOnSuspiciousPatterns(false)
                    .build();
            HTTPBodyValidationPipeline permissivePipeline = new HTTPBodyValidationPipeline(allowNullConfig, eventCounter);

            String nullByteContent = "content\u0000with\u0000nulls";
            String result = permissivePipeline.validate(nullByteContent);
            assertEquals(nullByteContent, result);
            assertFalse(eventCounter.hasAnyEvents());
        }

        @Test
        void shouldAllowControlCharactersWhenConfigured() {
            SecurityConfiguration allowControlConfig = SecurityConfiguration.builder()
                    .allowControlCharacters(true)
                    .failOnSuspiciousPatterns(false)
                    .build();
            HTTPBodyValidationPipeline permissivePipeline = new HTTPBodyValidationPipeline(allowControlConfig, eventCounter);

            String controlCharContent = "content\u0001\u0002";
            String result = permissivePipeline.validate(controlCharContent);
            assertEquals(controlCharContent, result);
            assertFalse(eventCounter.hasAnyEvents());
        }

        @Test
        void shouldHandleUnicodeContent() {
            String unicodeContent = "Content with émojis 🎉 and ünïcødé characters: café, naïve, résumé";
            String result = pipeline.validate(unicodeContent);
            assertEquals(unicodeContent, result);
            assertFalse(eventCounter.hasAnyEvents());
        }

        @Test
        void shouldHandleUnicodeNormalizationWhenEnabled() {
            SecurityConfiguration unicodeConfig = SecurityConfiguration.builder()
                    .normalizeUnicode(true)
                    .build();
            HTTPBodyValidationPipeline unicodePipeline = new HTTPBodyValidationPipeline(unicodeConfig, eventCounter);

            String decomposed = "cafe\u0301";
            String composed = "café";

            if (!decomposed.equals(composed)) {
                UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                        () -> unicodePipeline.validate(decomposed));

                assertEquals(ValidationType.BODY, exception.getValidationType());
                assertEquals(UrlSecurityFailureType.INVALID_CHARACTER, exception.getFailureType());
            } else {
                String result = unicodePipeline.validate(decomposed);
                assertEquals(decomposed, result);
            }
        }

        @Test
        void shouldHandleConfigurationEdgeCases() {
            SecurityConfiguration minimalConfig = SecurityConfiguration.builder()
                    .maxBodySize(1)
                    .build();
            HTTPBodyValidationPipeline minimalPipeline = new HTTPBodyValidationPipeline(minimalConfig, eventCounter);

            assertEquals("A", minimalPipeline.validate("A"));
            assertThrows(UrlSecurityException.class, () -> minimalPipeline.validate("AB"));

            SecurityConfiguration largeConfig = SecurityConfiguration.builder()
                    .maxBodySize(Long.MAX_VALUE)
                    .build();
            HTTPBodyValidationPipeline largePipeline = new HTTPBodyValidationPipeline(largeConfig, eventCounter);

            // QI-17: Replace 10KB hardcoded pattern with realistic body boundary testing
            String mediumBody = Generators.letterStrings(8000, 12000).next();
            assertEquals(mediumBody, largePipeline.validate(mediumBody));
        }
    }

    @Nested
    class PipelineBehavior {

        @Test
        void shouldSupportConditionalValidation() {
            var conditionalPipeline = pipeline.when(input -> input != null && input.length() > 10);

            String shortInput = "short";
            assertEquals(shortInput, conditionalPipeline.validate(shortInput));

            String longInput = "This is a longer input that should be validated";
            assertEquals(longInput, conditionalPipeline.validate(longInput));

            assertNull(conditionalPipeline.validate(null));
            assertFalse(eventCounter.hasAnyEvents());
        }

        @Test
        void shouldTrackSecurityEventsWhenRejectingAttacks() {
            SecurityEventCounter testCounter = new SecurityEventCounter();
            HTTPBodyValidationPipeline testPipeline = new HTTPBodyValidationPipeline(defaultConfig, testCounter);

            String attackContent = "malicious content\u0000with null byte";
            assertThrows(UrlSecurityException.class, () ->
                    testPipeline.validate(attackContent));
            assertTrue(testCounter.getTotalCount() > 0);
        }

        @Test
        void shouldBeImmutableAndThreadSafe() {
            assertDoesNotThrow(() -> HTTPBodyValidationPipeline.class.getMethod("equals", Object.class));
            assertDoesNotThrow(() -> HTTPBodyValidationPipeline.class.getMethod("hashCode"));
            assertDoesNotThrow(() -> HTTPBodyValidationPipeline.class.getMethod("toString"));

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

            for (Thread thread : threads) {
                thread.start();
            }
            for (Thread thread : threads) {
                assertDoesNotThrow(() -> thread.join());
            }

            for (boolean result : results) {
                assertTrue(result);
            }
        }

        @Test
        void shouldProvideMeaningfulToString() {
            String pipelineString = pipeline.toString();
            assertTrue(pipelineString.contains("HTTPBodyValidationPipeline"));
            assertTrue(pipelineString.contains("BODY"));
            assertTrue(pipelineString.contains("stages"));
            assertTrue(pipelineString.contains("eventCounter"));
        }

        @Test
        void shouldHandleMaxIntegerBodySize() {
            SecurityConfiguration maxIntConfig = SecurityConfiguration.builder()
                    .maxBodySize((long) Integer.MAX_VALUE + 1000L)
                    .build();

            HTTPBodyValidationPipeline maxIntPipeline = new HTTPBodyValidationPipeline(maxIntConfig, eventCounter);

            String content = "test content";
            assertEquals(content, maxIntPipeline.validate(content));
            assertFalse(eventCounter.hasAnyEvents());
        }

        @Test
        void shouldPreserveOriginalInputInException() {
            String originalInput = "<script>alert('test')</script>";

            UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                    () -> pipeline.validate(originalInput));

            assertEquals(originalInput, exception.getOriginalInput());
            assertEquals(ValidationType.BODY, exception.getValidationType());
        }
    }

    /**
     * QI-17: Generate realistic body content instead of using .repeat().
     * Creates varied content for HTTP body validation testing.
     */
    private String generateBodyContent(int length) {
        if (length <= 0) return "";

        // Use a much more efficient approach for all lengths
        StringBuilder result = new StringBuilder(length);
        String basePattern = "content_data_abcdefghij";

        int fullPatterns = length / basePattern.length();
        int remainder = length % basePattern.length();

        // Fill with complete patterns
        for (int i = 0; i < fullPatterns; i++) {
            result.append(basePattern);
        }

        // Add remainder
        if (remainder > 0) {
            result.append(basePattern, 0, remainder);
        }

        return result.toString();
    }
}