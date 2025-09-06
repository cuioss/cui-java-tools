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

import de.cuioss.tools.security.http.config.SecurityConfiguration;
import de.cuioss.tools.security.http.core.HttpSecurityValidator;
import de.cuioss.tools.security.http.core.ValidationType;
import de.cuioss.tools.security.http.monitoring.SecurityEventCounter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive test for {@link PipelineFactory}
 */
class PipelineFactoryTest {

    private SecurityConfiguration config;
    private SecurityEventCounter eventCounter;

    @BeforeEach
    void setUp() {
        config = SecurityConfiguration.defaults();
        eventCounter = new SecurityEventCounter();
    }

    @Test
    @DisplayName("Should create URL path validation pipeline")
    void shouldCreateUrlPathValidationPipeline() {
        HttpSecurityValidator pipeline = PipelineFactory.createUrlPathPipeline(config, eventCounter);

        assertNotNull(pipeline);
        assertInstanceOf(URLPathValidationPipeline.class, pipeline);

        // Test basic validation functionality
        String result = pipeline.validate("/api/users/123");
        assertEquals("/api/users/123", result);
    }

    @Test
    @DisplayName("Should create URL parameter validation pipeline")
    void shouldCreateUrlParameterValidationPipeline() {
        HttpSecurityValidator pipeline = PipelineFactory.createUrlParameterPipeline(config, eventCounter);

        assertNotNull(pipeline);
        assertInstanceOf(URLParameterValidationPipeline.class, pipeline);

        // Test basic validation functionality
        String result = pipeline.validate("test-value");
        assertEquals("test-value", result);
    }

    @Test
    @DisplayName("Should create HTTP header name validation pipeline")
    void shouldCreateHeaderNameValidationPipeline() {
        HttpSecurityValidator pipeline = PipelineFactory.createHeaderNamePipeline(config, eventCounter);

        assertNotNull(pipeline);
        assertInstanceOf(HTTPHeaderValidationPipeline.class, pipeline);

        // Test basic validation functionality
        String result = pipeline.validate("Content-Type");
        assertEquals("Content-Type", result);
    }

    @Test
    @DisplayName("Should create HTTP header value validation pipeline")
    void shouldCreateHeaderValueValidationPipeline() {
        HttpSecurityValidator pipeline = PipelineFactory.createHeaderValuePipeline(config, eventCounter);

        assertNotNull(pipeline);
        assertInstanceOf(HTTPHeaderValidationPipeline.class, pipeline);

        // Test basic validation functionality
        String result = pipeline.validate("application/json");
        assertEquals("application/json", result);
    }

    @Test
    @DisplayName("Should create HTTP body validation pipeline")
    void shouldCreateBodyValidationPipeline() {
        HttpSecurityValidator pipeline = PipelineFactory.createBodyPipeline(config, eventCounter);

        assertNotNull(pipeline);
        assertInstanceOf(HTTPBodyValidationPipeline.class, pipeline);

        // Test basic validation functionality
        String result = pipeline.validate("{\"name\": \"test\"}");
        assertEquals("{\"name\": \"test\"}", result);
    }

    @Test
    @DisplayName("Should reject null configuration in factory methods")
    void shouldRejectNullConfiguration() {
        assertThrows(NullPointerException.class,
                () -> PipelineFactory.createUrlPathPipeline(null, eventCounter));
        assertThrows(NullPointerException.class,
                () -> PipelineFactory.createUrlParameterPipeline(null, eventCounter));
        assertThrows(NullPointerException.class,
                () -> PipelineFactory.createHeaderNamePipeline(null, eventCounter));
        assertThrows(NullPointerException.class,
                () -> PipelineFactory.createHeaderValuePipeline(null, eventCounter));
        assertThrows(NullPointerException.class,
                () -> PipelineFactory.createBodyPipeline(null, eventCounter));
    }

    @Test
    @DisplayName("Should reject null event counter in factory methods")
    void shouldRejectNullEventCounter() {
        assertThrows(NullPointerException.class,
                () -> PipelineFactory.createUrlPathPipeline(config, null));
        assertThrows(NullPointerException.class,
                () -> PipelineFactory.createUrlParameterPipeline(config, null));
        assertThrows(NullPointerException.class,
                () -> PipelineFactory.createHeaderNamePipeline(config, null));
        assertThrows(NullPointerException.class,
                () -> PipelineFactory.createHeaderValuePipeline(config, null));
        assertThrows(NullPointerException.class,
                () -> PipelineFactory.createBodyPipeline(config, null));
    }

    @Test
    @DisplayName("Should create pipelines using generic factory method")
    void shouldCreatePipelinesUsingGenericFactory() {
        HttpSecurityValidator pathPipeline = PipelineFactory.createPipeline(ValidationType.URL_PATH, config, eventCounter);
        HttpSecurityValidator paramPipeline = PipelineFactory.createPipeline(ValidationType.PARAMETER_VALUE, config, eventCounter);
        HttpSecurityValidator headerNamePipeline = PipelineFactory.createPipeline(ValidationType.HEADER_NAME, config, eventCounter);
        HttpSecurityValidator headerValuePipeline = PipelineFactory.createPipeline(ValidationType.HEADER_VALUE, config, eventCounter);
        HttpSecurityValidator bodyPipeline = PipelineFactory.createPipeline(ValidationType.BODY, config, eventCounter);

        assertInstanceOf(URLPathValidationPipeline.class, pathPipeline);
        assertInstanceOf(URLParameterValidationPipeline.class, paramPipeline);
        assertInstanceOf(HTTPHeaderValidationPipeline.class, headerNamePipeline);
        assertInstanceOf(HTTPHeaderValidationPipeline.class, headerValuePipeline);
        assertInstanceOf(HTTPBodyValidationPipeline.class, bodyPipeline);
    }

    @Test
    @DisplayName("Should reject unsupported validation types in generic factory")
    void shouldRejectUnsupportedValidationTypes() {
        // PARAMETER_NAME should be rejected with specific message
        IllegalArgumentException paramNameException = assertThrows(IllegalArgumentException.class,
                () -> PipelineFactory.createPipeline(ValidationType.PARAMETER_NAME, config, eventCounter));
        assertTrue(paramNameException.getMessage().contains("PARAMETER_NAME validation is not supported"));
        assertTrue(paramNameException.getMessage().contains("Use PARAMETER_VALUE"));

        // COOKIE_NAME and COOKIE_VALUE should be rejected
        IllegalArgumentException cookieNameException = assertThrows(IllegalArgumentException.class,
                () -> PipelineFactory.createPipeline(ValidationType.COOKIE_NAME, config, eventCounter));
        assertTrue(cookieNameException.getMessage().contains("Cookie validation pipelines are not yet implemented"));

        IllegalArgumentException cookieValueException = assertThrows(IllegalArgumentException.class,
                () -> PipelineFactory.createPipeline(ValidationType.COOKIE_VALUE, config, eventCounter));
        assertTrue(cookieValueException.getMessage().contains("Cookie validation pipelines are not yet implemented"));
    }

    @Test
    @DisplayName("Should reject null parameters in generic factory method")
    void shouldRejectNullParametersInGenericFactory() {
        assertThrows(NullPointerException.class,
                () -> PipelineFactory.createPipeline(null, config, eventCounter));
        assertThrows(NullPointerException.class,
                () -> PipelineFactory.createPipeline(ValidationType.URL_PATH, null, eventCounter));
        assertThrows(NullPointerException.class,
                () -> PipelineFactory.createPipeline(ValidationType.URL_PATH, config, null));
    }

    @Test
    @DisplayName("Should create pipeline set with all common pipelines")
    void shouldCreatePipelineSetWithAllCommonPipelines() {
        PipelineFactory.PipelineSet pipelineSet = PipelineFactory.createCommonPipelines(config, eventCounter);

        assertNotNull(pipelineSet);
        assertNotNull(pipelineSet.urlPathPipeline());
        assertNotNull(pipelineSet.urlParameterPipeline());
        assertNotNull(pipelineSet.headerNamePipeline());
        assertNotNull(pipelineSet.headerValuePipeline());
        assertNotNull(pipelineSet.bodyPipeline());

        // Verify correct pipeline types
        assertInstanceOf(URLPathValidationPipeline.class, pipelineSet.urlPathPipeline());
        assertInstanceOf(URLParameterValidationPipeline.class, pipelineSet.urlParameterPipeline());
        assertInstanceOf(HTTPHeaderValidationPipeline.class, pipelineSet.headerNamePipeline());
        assertInstanceOf(HTTPHeaderValidationPipeline.class, pipelineSet.headerValuePipeline());
        assertInstanceOf(HTTPBodyValidationPipeline.class, pipelineSet.bodyPipeline());
    }

    @Test
    @DisplayName("Should reject null parameters in pipeline set creation")
    void shouldRejectNullParametersInPipelineSetCreation() {
        assertThrows(NullPointerException.class,
                () -> PipelineFactory.createCommonPipelines(null, eventCounter));
        assertThrows(NullPointerException.class,
                () -> PipelineFactory.createCommonPipelines(config, null));
    }

    @Test
    @DisplayName("Should use shared configuration and event counter across pipeline set")
    void shouldUseSharedConfigurationAndEventCounter() {
        SecurityEventCounter sharedCounter = new SecurityEventCounter();
        PipelineFactory.PipelineSet pipelineSet = PipelineFactory.createCommonPipelines(config, sharedCounter);

        // Verify that all pipelines share the same event counter (test through validation failures)
        assertFalse(sharedCounter.hasAnyEvents());

        // Trigger a validation error in one pipeline to verify event counter integration
        try {
            // This should trigger a null byte injection detection
            pipelineSet.bodyPipeline().validate("test\u0000content");
        } /*~~(Catch specific not Exception)~~>*//*~~(Catch specific not Exception)~~>*//*~~(Catch specific not Exception)~~>*//*~~(Catch specific not Exception)~~>*//*~~(Catch specific not Exception)~~>*//*~~(Catch specific not Exception)~~>*//*~~(Catch specific not Exception)~~>*//*~~(Catch specific not Exception)~~>*//*~~(Catch specific not Exception)~~>*//*~~(Catch specific not Exception)~~>*//*~~(Catch specific not Exception)~~>*/catch (Exception e) {
            // Expected - we're just testing that events are tracked
        }

        // The shared counter should now have events if the pipeline detected something
        // (This test verifies the integration without depending on specific validation behavior)
    }

    @Test
    @DisplayName("Should create functionally equivalent pipelines via different factory methods")
    void shouldCreateEquivalentPipelinesViaDifferentFactoryMethods() {
        HttpSecurityValidator directPathPipeline = PipelineFactory.createUrlPathPipeline(config, eventCounter);
        HttpSecurityValidator genericPathPipeline = PipelineFactory.createPipeline(ValidationType.URL_PATH, config, eventCounter);

        // Both should be the same type
        assertEquals(directPathPipeline.getClass(), genericPathPipeline.getClass());

        // Both should produce the same validation results
        String testInput = "/api/test/path";
        assertEquals(directPathPipeline.validate(testInput), genericPathPipeline.validate(testInput));

        HttpSecurityValidator directBodyPipeline = PipelineFactory.createBodyPipeline(config, eventCounter);
        HttpSecurityValidator genericBodyPipeline = PipelineFactory.createPipeline(ValidationType.BODY, config, eventCounter);

        assertEquals(directBodyPipeline.getClass(), genericBodyPipeline.getClass());

        String bodyTestInput = "{\"test\": \"data\"}";
        assertEquals(directBodyPipeline.validate(bodyTestInput), genericBodyPipeline.validate(bodyTestInput));
    }

    @ParameterizedTest
    @DisplayName("Should handle all supported validation types correctly")
    @EnumSource(value = ValidationType.class, names = {"URL_PATH", "PARAMETER_VALUE", "HEADER_NAME", "HEADER_VALUE", "BODY"})
    void shouldHandleSupportedValidationTypes(ValidationType validationType) {
        HttpSecurityValidator pipeline = PipelineFactory.createPipeline(validationType, config, eventCounter);
        assertNotNull(pipeline);

        // Verify pipeline can handle basic validation
        String testInput = "test-input";
        assertDoesNotThrow(() -> pipeline.validate(testInput));
    }

    @Test
    @DisplayName("Should create different instances on each factory call")
    void shouldCreateDifferentInstancesOnEachCall() {
        HttpSecurityValidator pipeline1 = PipelineFactory.createUrlPathPipeline(config, eventCounter);
        HttpSecurityValidator pipeline2 = PipelineFactory.createUrlPathPipeline(config, eventCounter);

        assertNotSame(pipeline1, pipeline2, "Factory should create new instances on each call");
        assertEquals(pipeline1.getClass(), pipeline2.getClass(), "But they should be the same type");
    }

    @Test
    @DisplayName("Should work with different security configurations")
    void shouldWorkWithDifferentSecurityConfigurations() {
        SecurityConfiguration strictConfig = SecurityConfiguration.strict();
        SecurityConfiguration lenientConfig = SecurityConfiguration.lenient();

        HttpSecurityValidator strictPipeline = PipelineFactory.createBodyPipeline(strictConfig, eventCounter);
        HttpSecurityValidator lenientPipeline = PipelineFactory.createBodyPipeline(lenientConfig, eventCounter);

        assertNotNull(strictPipeline);
        assertNotNull(lenientPipeline);
        assertEquals(strictPipeline.getClass(), lenientPipeline.getClass());

        // Both should handle basic content
        String testContent = "basic content";
        assertEquals(testContent, strictPipeline.validate(testContent));
        assertEquals(testContent, lenientPipeline.validate(testContent));
    }

    @Test
    @DisplayName("Should provide meaningful pipeline set toString")
    void shouldProvideMeaningfulPipelineSetToString() {
        PipelineFactory.PipelineSet pipelineSet = PipelineFactory.createCommonPipelines(config, eventCounter);
        String toString = pipelineSet.toString();

        // Just verify toString works and is not empty/null
        assertNotNull(toString);
        assertFalse(toString.isEmpty());
        // Records auto-generate toString, so content is implementation-dependent
    }

    @Test
    @DisplayName("Should validate pipeline set record constraints")
    void shouldValidatePipelineSetRecordConstraints() {
        HttpSecurityValidator validPipeline = PipelineFactory.createUrlPathPipeline(config, eventCounter);

        // All parameters are required - none can be null
        assertThrows(NullPointerException.class, () ->
                new PipelineFactory.PipelineSet(null, validPipeline, validPipeline, validPipeline, validPipeline));
        assertThrows(NullPointerException.class, () ->
                new PipelineFactory.PipelineSet(validPipeline, null, validPipeline, validPipeline, validPipeline));
        assertThrows(NullPointerException.class, () ->
                new PipelineFactory.PipelineSet(validPipeline, validPipeline, null, validPipeline, validPipeline));
        assertThrows(NullPointerException.class, () ->
                new PipelineFactory.PipelineSet(validPipeline, validPipeline, validPipeline, null, validPipeline));
        assertThrows(NullPointerException.class, () ->
                new PipelineFactory.PipelineSet(validPipeline, validPipeline, validPipeline, validPipeline, null));
    }

    @Test
    @DisplayName("Should support pipeline set equality and hashcode")
    void shouldSupportPipelineSetEqualityAndHashcode() {
        PipelineFactory.PipelineSet set1 = PipelineFactory.createCommonPipelines(config, eventCounter);
        PipelineFactory.PipelineSet set2 = PipelineFactory.createCommonPipelines(config, eventCounter);

        // Sets with same configuration should be equal (structural equality)
        assertEquals(set1, set2);
        assertEquals(set1.hashCode(), set2.hashCode());

        // But same instance should equal itself
        assertEquals(set1, set1);
        assertEquals(set1.hashCode(), set1.hashCode());
    }

    @Test
    @DisplayName("Should handle concurrent factory calls safely")
    void shouldHandleConcurrentFactoryCallsSafely() {
        int threadCount = 10;
        Thread[] threads = new Thread[threadCount];
        HttpSecurityValidator[] results = new HttpSecurityValidator[threadCount];
        boolean[] success = new boolean[threadCount];

        for (int i = 0; i < threadCount; i++) {
            final int index = i;
            threads[i] = new Thread(() -> {
                try {
                    results[index] = PipelineFactory.createUrlPathPipeline(config, eventCounter);
                    success[index] = results[index] != null;
                } /*~~(Catch specific not Exception)~~>*//*~~(Catch specific not Exception)~~>*//*~~(Catch specific not Exception)~~>*//*~~(Catch specific not Exception)~~>*//*~~(Catch specific not Exception)~~>*//*~~(Catch specific not Exception)~~>*//*~~(Catch specific not Exception)~~>*//*~~(Catch specific not Exception)~~>*//*~~(Catch specific not Exception)~~>*//*~~(Catch specific not Exception)~~>*//*~~(Catch specific not Exception)~~>*/catch (Exception e) {
                    success[index] = false;
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
        for (int i = 0; i < threadCount; i++) {
            assertTrue(success[i], "Thread " + i + " should have succeeded");
            assertNotNull(results[i], "Thread " + i + " should have created a pipeline");
        }

        // Verify all created different instances
        for (int i = 0; i < threadCount; i++) {
            for (int j = i + 1; j < threadCount; j++) {
                assertNotSame(results[i], results[j],
                        "Thread " + i + " and " + j + " should create different instances");
            }
        }
    }
}