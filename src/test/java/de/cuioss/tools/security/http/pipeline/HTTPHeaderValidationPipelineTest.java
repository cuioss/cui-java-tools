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
import de.cuioss.tools.security.http.core.UrlSecurityFailureType;
import de.cuioss.tools.security.http.core.ValidationType;
import de.cuioss.tools.security.http.exceptions.UrlSecurityException;
import de.cuioss.tools.security.http.generators.HTTPHeaderInjectionGenerator;
import de.cuioss.tools.security.http.generators.InvalidHTTPHeaderNameGenerator;
import de.cuioss.tools.security.http.generators.ValidHTTPHeaderNameGenerator;
import de.cuioss.tools.security.http.generators.ValidHTTPHeaderValueGenerator;
import de.cuioss.tools.security.http.monitoring.SecurityEventCounter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;

import static org.junit.jupiter.api.Assertions.*;

@EnableGeneratorController
class HTTPHeaderValidationPipelineTest {

    private SecurityConfiguration config;
    private SecurityEventCounter eventCounter;

    @BeforeEach
    void setUp() {
        config = SecurityConfiguration.defaults();
        eventCounter = new SecurityEventCounter();
    }

    @Nested
    class PipelineCreation {

        @Test
        void shouldCreatePipelineForHeaderName() {
            HTTPHeaderValidationPipeline pipeline = new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_NAME);

            assertEquals(ValidationType.HEADER_NAME, pipeline.getValidationType());
            assertEquals(4, pipeline.getStages().size());
            assertSame(eventCounter, pipeline.getEventCounter());
        }

        @Test
        void shouldCreatePipelineForHeaderValue() {
            HTTPHeaderValidationPipeline pipeline = new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_VALUE);

            assertEquals(ValidationType.HEADER_VALUE, pipeline.getValidationType());
            assertEquals(4, pipeline.getStages().size());
            assertSame(eventCounter, pipeline.getEventCounter());
        }

        @Test
        void shouldRejectNullConfig() {
            assertThrows(NullPointerException.class, () ->
                    new HTTPHeaderValidationPipeline(null, eventCounter, ValidationType.HEADER_VALUE));
        }

        @Test
        void shouldRejectNullEventCounter() {
            assertThrows(NullPointerException.class, () ->
                    new HTTPHeaderValidationPipeline(config, null, ValidationType.HEADER_VALUE));
        }

        @Test
        void shouldRejectNullValidationType() {
            assertThrows(NullPointerException.class, () ->
                    new HTTPHeaderValidationPipeline(config, eventCounter, null));
        }

        @Test
        void shouldRejectNonHeaderValidationType() {
            assertThrows(IllegalArgumentException.class, () ->
                    new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.URL_PATH));

            assertThrows(IllegalArgumentException.class, () ->
                    new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.PARAMETER_VALUE));

            assertThrows(IllegalArgumentException.class, () ->
                    new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.BODY));
        }
    }

    @Nested
    class ValidInputHandling {

        @ParameterizedTest
        @TypeGeneratorSource(value = ValidHTTPHeaderNameGenerator.class, count = 10)
        void shouldAcceptValidHeaderNames(String validHeaderName) throws UrlSecurityException {
            HTTPHeaderValidationPipeline pipeline = new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_NAME);

            String result = pipeline.validate(validHeaderName);
            assertNotNull(result);
            assertEquals(validHeaderName, result);
        }

        @ParameterizedTest
        @TypeGeneratorSource(value = ValidHTTPHeaderValueGenerator.class, count = 10)
        void shouldAcceptValidHeaderValues(String validHeaderValue) throws UrlSecurityException {
            HTTPHeaderValidationPipeline pipeline = new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_VALUE);

            String result = pipeline.validate(validHeaderValue);
            assertNotNull(result);
            assertEquals(validHeaderValue, result);
        }

        @Test
        void shouldHandleNullInput() throws UrlSecurityException {
            HTTPHeaderValidationPipeline pipeline = new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_VALUE);

            String result = pipeline.validate(null);
            assertNull(result);
        }

        @Test
        void shouldHandleEmptyInput() throws UrlSecurityException {
            HTTPHeaderValidationPipeline pipeline = new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_VALUE);

            String result = pipeline.validate("");
            assertEquals("", result);
        }
    }

    @Nested
    class SecurityValidation {

        @ParameterizedTest
        @TypeGeneratorSource(value = HTTPHeaderInjectionGenerator.class, count = 5)
        void shouldRejectHeaderInjectionVariants(String maliciousHeader) {
            HTTPHeaderValidationPipeline pipeline = new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_VALUE);

            assertThrows(UrlSecurityException.class, () ->
                    pipeline.validate(maliciousHeader));
        }

        @ParameterizedTest
        @TypeGeneratorSource(value = InvalidHTTPHeaderNameGenerator.class, count = 5)
        void shouldRejectInvalidHeaderNames(String maliciousHeaderName) {
            HTTPHeaderValidationPipeline pipeline = new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_NAME);

            assertThrows(UrlSecurityException.class, () ->
                    pipeline.validate(maliciousHeaderName));
        }

        @Test
        void shouldRejectOversizedHeaderValue() {
            HTTPHeaderValidationPipeline pipeline = new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_VALUE);

            String oversizedHeader = "x".repeat(config.maxHeaderValueLength() + 100);
            assertThrows(UrlSecurityException.class, () ->
                    pipeline.validate(oversizedHeader));
        }

        @Test
        void shouldRejectHeaderValueTooLong() {
            HTTPHeaderValidationPipeline pipeline = new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_VALUE);

            String longHeaderValue = "Bearer " + "a".repeat(config.maxHeaderValueLength());

            UrlSecurityException exception = assertThrows(UrlSecurityException.class, () ->
                    pipeline.validate(longHeaderValue));

            assertEquals(UrlSecurityFailureType.INPUT_TOO_LONG, exception.getFailureType());
            assertEquals(ValidationType.HEADER_VALUE, exception.getValidationType());
            assertEquals(longHeaderValue, exception.getOriginalInput());
        }

        @Test
        void shouldRejectHeaderNameTooLong() {
            HTTPHeaderValidationPipeline pipeline = new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_NAME);

            String longHeaderName = "X-Custom-" + "Header".repeat(config.maxHeaderNameLength() / 6);

            UrlSecurityException exception = assertThrows(UrlSecurityException.class, () ->
                    pipeline.validate(longHeaderName));

            assertEquals(UrlSecurityFailureType.INPUT_TOO_LONG, exception.getFailureType());
            assertEquals(ValidationType.HEADER_NAME, exception.getValidationType());
            assertEquals(longHeaderName, exception.getOriginalInput());
        }
    }

    @Nested
    class PipelineBehavior {

        @Test
        void shouldSequentiallyApplyStages() {
            HTTPHeaderValidationPipeline pipeline = new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_VALUE);

            String problematicHeader = "Bearer " + "token with\r\ninjection".repeat(1000);

            UrlSecurityException exception = assertThrows(UrlSecurityException.class, () ->
                    pipeline.validate(problematicHeader));

            assertEquals(UrlSecurityFailureType.INPUT_TOO_LONG, exception.getFailureType());
        }

        @ParameterizedTest
        @TypeGeneratorSource(value = HTTPHeaderInjectionGenerator.class, count = 10)
        void shouldRejectHeaderInjectionAttacksAndTrackEvents(String attackHeader) {
            HTTPHeaderValidationPipeline pipeline = new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_VALUE);

            assertThrows(UrlSecurityException.class, () ->
                    pipeline.validate(attackHeader));
            assertTrue(eventCounter.getTotalCount() > 0);
        }

        @Test
        void shouldHaveCorrectEqualsAndHashCode() {
            HTTPHeaderValidationPipeline pipeline1 = new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_VALUE);
            HTTPHeaderValidationPipeline pipeline2 = new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_VALUE);

            assertEquals(pipeline1, pipeline2);
            assertEquals(pipeline1.hashCode(), pipeline2.hashCode());

            HTTPHeaderValidationPipeline pipeline3 = new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_NAME);
            assertNotEquals(pipeline1, pipeline3);
        }

        @Test
        void shouldHaveCorrectToString() {
            HTTPHeaderValidationPipeline pipeline = new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_VALUE);

            String toString = pipeline.toString();
            assertTrue(toString.contains("HTTPHeaderValidationPipeline"));
        }

        @Test
        void shouldPreserveStageOrder() {
            HTTPHeaderValidationPipeline pipeline = new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_VALUE);

            var stages = pipeline.getStages();
            assertEquals(4, stages.size());

            assertTrue(stages.getFirst().getClass().getSimpleName().contains("Length"));
            assertTrue(stages.get(1).getClass().getSimpleName().contains("Character"));
            assertTrue(stages.get(2).getClass().getSimpleName().contains("Normalization"));
            assertTrue(stages.get(3).getClass().getSimpleName().contains("Pattern"));
        }
    }

    @Nested
    class ValidationTypeSpecific {

        @Test
        void shouldHandleDifferentValidationTypes() {
            HTTPHeaderValidationPipeline namesPipeline = new HTTPHeaderValidationPipeline(
                    config, eventCounter, ValidationType.HEADER_NAME);
            HTTPHeaderValidationPipeline valuesPipeline = new HTTPHeaderValidationPipeline(
                    config, eventCounter, ValidationType.HEADER_VALUE);

            assertEquals(ValidationType.HEADER_NAME, namesPipeline.getValidationType());
            assertEquals(ValidationType.HEADER_VALUE, valuesPipeline.getValidationType());
        }
    }
}