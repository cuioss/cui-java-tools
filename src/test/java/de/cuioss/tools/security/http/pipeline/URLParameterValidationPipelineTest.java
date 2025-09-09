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
import de.cuioss.tools.security.http.generators.encoding.EncodingCombinationGenerator;
import de.cuioss.tools.security.http.generators.url.NullByteInjectionParameterGenerator;
import de.cuioss.tools.security.http.generators.url.PathTraversalParameterGenerator;
import de.cuioss.tools.security.http.generators.url.ValidURLParameterStringGenerator;
import de.cuioss.tools.security.http.monitoring.SecurityEventCounter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;

import static org.junit.jupiter.api.Assertions.*;

@EnableGeneratorController
class URLParameterValidationPipelineTest {

    private SecurityConfiguration config;
    private SecurityEventCounter eventCounter;
    private URLParameterValidationPipeline pipeline;

    @BeforeEach
    void setUp() {
        config = SecurityConfiguration.defaults();
        eventCounter = new SecurityEventCounter();
        pipeline = new URLParameterValidationPipeline(config, eventCounter);
    }

    @Nested
    class PipelineCreation {

        @Test
        void shouldCreatePipelineWithValidParameters() {
            assertEquals(ValidationType.PARAMETER_VALUE, pipeline.getValidationType(), "Pipeline should have correct validation type");
            assertEquals(5, pipeline.getStages().size(), "Pipeline should have 5 validation stages");
            assertSame(eventCounter, pipeline.getEventCounter(), "Pipeline should use the provided event counter");
        }

        @Test
        void shouldRejectNullConfig() {
            assertThrows(NullPointerException.class, () ->
                    new URLParameterValidationPipeline(null, eventCounter));
        }

        @Test
        void shouldRejectNullEventCounter() {
            assertThrows(NullPointerException.class, () ->
                    new URLParameterValidationPipeline(config, null));
        }
    }

    @Nested
    class ValidInputHandling {

        @ParameterizedTest
        @TypeGeneratorSource(value = ValidURLParameterStringGenerator.class, count = 10)
        void shouldValidateValidParameters(String validParam) throws UrlSecurityException {
            String result = pipeline.validate(validParam);
            assertNotNull(result, "Valid parameter should not return null result");
        }

        @Test
        void shouldHandleNullInput() throws UrlSecurityException {
            String result = pipeline.validate(null);
            assertNull(result, "Null input should return null result");
        }

        @Test
        void shouldHandleEmptyInput() throws UrlSecurityException {
            String result = pipeline.validate("");
            assertEquals("", result, "Empty input should return empty string result");
        }
    }

    @Nested
    class SecurityValidation {

        @ParameterizedTest
        @TypeGeneratorSource(value = ValidURLParameterStringGenerator.class, count = 5)
        void shouldValidateParameterVariations(String param) throws UrlSecurityException {
            String result = pipeline.validate(param);
            assertNotNull(result, "Valid parameter variation should not return null result");
        }

        @ParameterizedTest
        @TypeGeneratorSource(value = NullByteInjectionParameterGenerator.class, count = 5)
        void shouldRejectNullByteInjection(String maliciousParam) {
            UrlSecurityException exception = assertThrows(UrlSecurityException.class, () ->
                    pipeline.validate(maliciousParam));

            assertEquals(UrlSecurityFailureType.NULL_BYTE_INJECTION, exception.getFailureType(), "Exception should indicate null byte injection failure");
            assertEquals(ValidationType.PARAMETER_VALUE, exception.getValidationType(), "Exception should indicate parameter value validation type");
            assertEquals(maliciousParam, exception.getOriginalInput(), "Exception should preserve original malicious input");
        }

        @Test
        void shouldRejectSpecificPathTraversalValues() {
            // Test parameter values (correct usage for URLParameterValidationPipeline)
            String valueOnly1 = "..%2F..%2Fetc%2Fpasswd";
            String valueOnly2 = "%2E%2E%2F%2E%2E%2Fconfig";

            assertThrows(UrlSecurityException.class, () ->
                            pipeline.validate(valueOnly1),
                    "Pipeline should reject encoded path traversal pattern: " + valueOnly1);

            assertThrows(UrlSecurityException.class, () ->
                            pipeline.validate(valueOnly2),
                    "Pipeline should reject encoded path traversal pattern: " + valueOnly2);

            // Test decoded patterns (should also be detected)
            String decoded1 = "../../../etc/passwd";
            String decoded2 = "../../config";

            assertThrows(UrlSecurityException.class, () ->
                            pipeline.validate(decoded1),
                    "Pipeline should reject decoded path traversal pattern: " + decoded1);

            assertThrows(UrlSecurityException.class, () ->
                            pipeline.validate(decoded2),
                    "Pipeline should reject decoded path traversal pattern: " + decoded2);
        }

        @ParameterizedTest
        @TypeGeneratorSource(value = PathTraversalParameterGenerator.class, count = 5)
        void shouldRejectPathTraversalVariants(String maliciousParam) {
            assertThrows(UrlSecurityException.class, () ->
                    pipeline.validate(maliciousParam));
        }

        @ParameterizedTest
        @TypeGeneratorSource(value = EncodingCombinationGenerator.class, count = 5)
        void shouldRejectEncodingBypassAttacks(String encodedParam) {
            assertThrows(UrlSecurityException.class, () ->
                    pipeline.validate(encodedParam));
        }

        @Test
        void shouldRejectOversizedParameter() {
            String oversizedParam = "x".repeat(config.maxParameterValueLength() + 100);
            assertThrows(UrlSecurityException.class, () ->
                    pipeline.validate(oversizedParam));
        }
    }

    @Nested
    class ParameterSpecificScenarios {

        @ParameterizedTest
        @TypeGeneratorSource(value = ValidURLParameterStringGenerator.class, count = 5)
        void shouldValidateParameterSpecificScenarios(String validParam) throws UrlSecurityException {
            String result = pipeline.validate(validParam);
            assertNotNull(result, "Valid parameter in specific scenarios should not return null result");
        }

        @ParameterizedTest
        @TypeGeneratorSource(value = PathTraversalParameterGenerator.class, count = 3)
        void shouldRejectPathTraversalInParameters(String traversalParam) {
            assertThrows(UrlSecurityException.class, () ->
                    pipeline.validate(traversalParam));
        }
    }

    @Nested
    class PipelineBehavior {

        @Test
        void shouldSequentiallyApplyStages() {
            String problematicParam = "param=" + "invalid\tvalue".repeat(1000);

            UrlSecurityException exception = assertThrows(UrlSecurityException.class, () ->
                    pipeline.validate(problematicParam));

            assertEquals(UrlSecurityFailureType.INPUT_TOO_LONG, exception.getFailureType(), "Pipeline should reject input that exceeds length limits");
        }

        @ParameterizedTest
        @TypeGeneratorSource(value = PathTraversalParameterGenerator.class, count = 5)
        void shouldTrackSecurityEventsWhenRejectingAttacks(String attackParam) {
            assertThrows(UrlSecurityException.class, () ->
                    pipeline.validate(attackParam));
            assertTrue(eventCounter.getTotalCount() > 0, "Security events should be tracked when attacks are rejected");
        }

        @Test
        void shouldHaveCorrectEqualsAndHashCode() {
            URLParameterValidationPipeline pipeline1 = new URLParameterValidationPipeline(config, eventCounter);
            URLParameterValidationPipeline pipeline2 = new URLParameterValidationPipeline(config, eventCounter);

            assertEquals(pipeline1, pipeline2, "Pipelines with same configuration should be equal");
            assertEquals(pipeline1.hashCode(), pipeline2.hashCode(), "Equal pipelines should have same hash code");
        }

        @Test
        void shouldHaveCorrectToString() {
            String toString = pipeline.toString();
            assertTrue(toString.contains("URLParameterValidationPipeline"), "toString should contain pipeline class name");
        }

        @Test
        void shouldPreserveStageOrder() {
            var stages = pipeline.getStages();
            assertEquals(5, stages.size(), "Pipeline should have exactly 5 stages in correct order");

            assertTrue(stages.getFirst().getClass().getSimpleName().contains("Length"), "First stage should be length validation");
            assertTrue(stages.get(1).getClass().getSimpleName().contains("Character"), "Second stage should be character validation");
            assertTrue(stages.get(2).getClass().getSimpleName().contains("Decoding"), "Third stage should be decoding validation");
            assertTrue(stages.get(3).getClass().getSimpleName().contains("Normalization"), "Fourth stage should be normalization validation");
            assertTrue(stages.get(4).getClass().getSimpleName().contains("Pattern"), "Fifth stage should be pattern validation");
        }
    }
}