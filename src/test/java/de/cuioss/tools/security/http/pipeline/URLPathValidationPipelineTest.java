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
import de.cuioss.tools.security.http.generators.encoding.UnicodeAttackGenerator;
import de.cuioss.tools.security.http.generators.url.NullByteURLGenerator;
import de.cuioss.tools.security.http.generators.url.PathTraversalURLGenerator;
import de.cuioss.tools.security.http.generators.url.ValidURLPathGenerator;
import de.cuioss.tools.security.http.monitoring.SecurityEventCounter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;

import static org.junit.jupiter.api.Assertions.*;

@EnableGeneratorController
class URLPathValidationPipelineTest {

    private SecurityConfiguration config;
    private SecurityEventCounter eventCounter;
    private URLPathValidationPipeline pipeline;

    @BeforeEach
    void setUp() {
        config = SecurityConfiguration.defaults();
        eventCounter = new SecurityEventCounter();
        pipeline = new URLPathValidationPipeline(config, eventCounter);
    }

    @Nested
    class PipelineCreation {

        @Test
        void shouldCreatePipelineWithValidParameters() {
            assertEquals(ValidationType.URL_PATH, pipeline.getValidationType());
            assertEquals(6, pipeline.getStages().size());
            assertSame(eventCounter, pipeline.getEventCounter());
        }

        @Test
        void shouldRejectNullConfig() {
            assertThrows(NullPointerException.class, () ->
                    new URLPathValidationPipeline(null, eventCounter));
        }

        @Test
        void shouldRejectNullEventCounter() {
            assertThrows(NullPointerException.class, () ->
                    new URLPathValidationPipeline(config, null));
        }
    }

    @Nested
    class ValidInputHandling {

        @ParameterizedTest
        @TypeGeneratorSource(value = ValidURLPathGenerator.class, count = 10)
        void shouldValidateValidPaths(String validPath) throws UrlSecurityException {
            String result = pipeline.validate(validPath);
            assertNotNull(result);
        }

        @Test
        void shouldHandleNullInput() throws UrlSecurityException {
            String result = pipeline.validate(null);
            assertNull(result);
        }

        @Test
        void shouldHandleEmptyInput() throws UrlSecurityException {
            String result = pipeline.validate("");
            assertEquals("", result);
        }
    }

    @Nested
    class SecurityValidation {

        @ParameterizedTest
        @TypeGeneratorSource(value = PathTraversalURLGenerator.class, count = 5)
        void shouldRejectPathTraversalAttacks(String traversalPath) {
            assertThrows(UrlSecurityException.class, () ->
                    pipeline.validate(traversalPath));
        }

        @ParameterizedTest
        @TypeGeneratorSource(value = NullByteURLGenerator.class, count = 5)
        void shouldRejectNullByteInjection(String maliciousPath) {
            UrlSecurityException exception = assertThrows(UrlSecurityException.class, () ->
                    pipeline.validate(maliciousPath));

            assertEquals(UrlSecurityFailureType.NULL_BYTE_INJECTION, exception.getFailureType());
            assertEquals(ValidationType.URL_PATH, exception.getValidationType());
            assertEquals(maliciousPath, exception.getOriginalInput());
        }

        @ParameterizedTest
        @TypeGeneratorSource(value = PathTraversalURLGenerator.class, count = 5)
        void shouldRejectPathTraversal(String traversalPath) {
            UrlSecurityException exception = assertThrows(UrlSecurityException.class, () ->
                    pipeline.validate(traversalPath));

            assertTrue(exception.getFailureType() == UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED ||
                    exception.getFailureType() == UrlSecurityFailureType.DIRECTORY_ESCAPE_ATTEMPT ||
                    exception.getFailureType() == UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED);
            assertEquals(ValidationType.URL_PATH, exception.getValidationType());
        }

        @ParameterizedTest
        @TypeGeneratorSource(value = EncodingCombinationGenerator.class, count = 5)
        void shouldRejectEncodingBypassAttacks(String encodedPath) {
            assertThrows(UrlSecurityException.class, () ->
                    pipeline.validate(encodedPath));
        }

        @ParameterizedTest
        @TypeGeneratorSource(value = UnicodeAttackGenerator.class, count = 5)
        void shouldRejectUnicodeAttacks(String unicodePath) {
            assertThrows(UrlSecurityException.class, () ->
                    pipeline.validate(unicodePath));
        }

        @Test
        void shouldRejectOversizedPath() {
            String oversizedPath = "/" + generatePathContent(config.maxPathLength());
            assertThrows(UrlSecurityException.class, () ->
                    pipeline.validate(oversizedPath));
        }
    }

    @Nested
    class PipelineBehavior {

        @Test
        void shouldSequentiallyApplyStages() {
            String problematicPath = "/" + generateRepeatedPattern("invalid path with spaces", 1000);

            UrlSecurityException exception = assertThrows(UrlSecurityException.class, () ->
                    pipeline.validate(problematicPath));

            assertEquals(UrlSecurityFailureType.PATH_TOO_LONG, exception.getFailureType());
        }

        @ParameterizedTest
        @TypeGeneratorSource(value = PathTraversalURLGenerator.class, count = 5)
        void shouldTrackSecurityEventsWhenRejectingAttacks(String attackPath) {
            assertThrows(UrlSecurityException.class, () ->
                    pipeline.validate(attackPath));
            assertTrue(eventCounter.getTotalCount() > 0);
        }

        @Test
        void shouldHaveCorrectEqualsAndHashCode() {
            URLPathValidationPipeline pipeline1 = new URLPathValidationPipeline(config, eventCounter);
            URLPathValidationPipeline pipeline2 = new URLPathValidationPipeline(config, eventCounter);

            assertEquals(pipeline1, pipeline2);
            assertEquals(pipeline1.hashCode(), pipeline2.hashCode());
        }

        @Test
        void shouldHaveCorrectToString() {
            String toString = pipeline.toString();
            assertTrue(toString.contains("URLPathValidationPipeline"));
        }

        @Test
        void shouldPreserveStageOrder() {
            var stages = pipeline.getStages();
            assertEquals(6, stages.size());

            assertTrue(stages.getFirst().getClass().getSimpleName().contains("Length"));
            assertTrue(stages.get(1).getClass().getSimpleName().contains("Character"));
            assertTrue(stages.get(2).getClass().getSimpleName().contains("Pattern"));
            assertTrue(stages.get(3).getClass().getSimpleName().contains("Decoding"));
            assertTrue(stages.get(4).getClass().getSimpleName().contains("Normalization"));
            assertTrue(stages.get(5).getClass().getSimpleName().contains("Pattern"));
        }
    }

    /**
     * QI-17: Generate realistic path content instead of using .repeat().
     * Creates varied path content for URL validation testing.
     */
    private String generatePathContent(int length) {
        StringBuilder result = new StringBuilder();
        String[] segments = {"api", "data", "user", "admin", "config", "test"};

        for (int i = 0; i < length; i++) {
            if (i % 20 == 0 && i > 0) {
                result.append("/").append(segments[i / 20 % segments.length]);
                i += segments[i / 20 % segments.length].length() + 1;
                if (i >= length) break;
            }
            result.append((char) ('a' + (i % 26)));
        }

        // Ensure exact length
        String generated = result.toString();
        return generated.length() > length ? generated.substring(0, length) : generated;
    }

    /**
     * QI-17: Generate realistic repeated patterns instead of using .repeat().
     */
    private String generateRepeatedPattern(String pattern, int count) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < count; i++) {
            result.append(pattern);
            if (i % 10 == 9) {
                result.append(i % 10);
            }
        }
        return result.toString();
    }
}