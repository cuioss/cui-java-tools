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
import de.cuioss.tools.security.http.core.UrlSecurityFailureType;
import de.cuioss.tools.security.http.core.ValidationType;
import de.cuioss.tools.security.http.exceptions.UrlSecurityException;
import de.cuioss.tools.security.http.monitoring.SecurityEventCounter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

class HTTPHeaderValidationPipelineTest {

    private SecurityConfiguration config;
    private SecurityEventCounter eventCounter;

    @BeforeEach
    void setUp() {
        config = SecurityConfiguration.defaults();
        eventCounter = new SecurityEventCounter();
    }

    @Test
    void shouldCreatePipelineForHeaderName() {
        HTTPHeaderValidationPipeline pipeline = new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_NAME);

        assertNotNull(pipeline);
        assertEquals(ValidationType.HEADER_NAME, pipeline.getValidationType());
        assertEquals(4, pipeline.getStages().size()); // 4 validation stages (no decoding for headers)
        assertSame(eventCounter, pipeline.getEventCounter());
    }

    @Test
    void shouldCreatePipelineForHeaderValue() {
        HTTPHeaderValidationPipeline pipeline = new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_VALUE);

        assertNotNull(pipeline);
        assertEquals(ValidationType.HEADER_VALUE, pipeline.getValidationType());
        assertEquals(4, pipeline.getStages().size()); // 4 validation stages (no decoding for headers)
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

    @Test
    void shouldValidateSimpleHeaderName() throws UrlSecurityException {
        HTTPHeaderValidationPipeline pipeline = new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_NAME);

        String validHeaderName = "Authorization";
        String result = pipeline.validate(validHeaderName);
        assertEquals("Authorization", result);
    }

    @Test
    void shouldValidateSimpleHeaderValue() throws UrlSecurityException {
        HTTPHeaderValidationPipeline pipeline = new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_VALUE);

        String validHeaderValue = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        String result = pipeline.validate(validHeaderValue);
        assertEquals("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", result);
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

    @Test
    void shouldRejectHeaderValueTooLong() {
        HTTPHeaderValidationPipeline pipeline = new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_VALUE);

        // Create a header value that exceeds the maximum length
        String longHeaderValue = "Bearer " + "a".repeat(config.maxHeaderValueLength());

        UrlSecurityException exception = assertThrows(UrlSecurityException.class, () ->
                pipeline.validate(longHeaderValue));

        assertEquals(UrlSecurityFailureType.INPUT_TOO_LONG, exception.getFailureType());
        assertEquals(ValidationType.HEADER_VALUE, exception.getValidationType());
        assertEquals(longHeaderValue, exception.getOriginalInput());

        // Verify event counter was incremented
        assertEquals(1, eventCounter.getCount(UrlSecurityFailureType.INPUT_TOO_LONG));
    }

    @Test
    void shouldRejectHeaderNameTooLong() {
        HTTPHeaderValidationPipeline pipeline = new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_NAME);

        // Create a header name that exceeds the maximum length
        String longHeaderName = "X-Custom-" + "Header".repeat(config.maxHeaderNameLength() / 6);

        UrlSecurityException exception = assertThrows(UrlSecurityException.class, () ->
                pipeline.validate(longHeaderName));

        assertEquals(UrlSecurityFailureType.INPUT_TOO_LONG, exception.getFailureType());
        assertEquals(ValidationType.HEADER_NAME, exception.getValidationType());
        assertEquals(longHeaderName, exception.getOriginalInput());

        // Verify event counter was incremented
        assertEquals(1, eventCounter.getCount(UrlSecurityFailureType.INPUT_TOO_LONG));
    }

    @Test
    void shouldRejectHeaderInjection() {
        HTTPHeaderValidationPipeline pipeline = new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_VALUE);

        String headerWithCRLF = "Bearer token\r\nX-Injected-Header: malicious";

        UrlSecurityException exception = assertThrows(UrlSecurityException.class, () ->
                pipeline.validate(headerWithCRLF));

        assertEquals(UrlSecurityFailureType.INVALID_CHARACTER, exception.getFailureType());
        assertEquals(ValidationType.HEADER_VALUE, exception.getValidationType());
        assertEquals(headerWithCRLF, exception.getOriginalInput());

        // Verify event counter was incremented
        assertEquals(1, eventCounter.getCount(UrlSecurityFailureType.INVALID_CHARACTER));
    }

    @Test
    void shouldRejectNullByteInjection() {
        HTTPHeaderValidationPipeline pipeline = new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_VALUE);

        String maliciousHeader = "Bearer token\0admin";

        UrlSecurityException exception = assertThrows(UrlSecurityException.class, () ->
                pipeline.validate(maliciousHeader));

        assertEquals(UrlSecurityFailureType.NULL_BYTE_INJECTION, exception.getFailureType());
        assertEquals(ValidationType.HEADER_VALUE, exception.getValidationType());
        assertEquals(maliciousHeader, exception.getOriginalInput());

        // Verify event counter was incremented
        assertEquals(1, eventCounter.getCount(UrlSecurityFailureType.NULL_BYTE_INJECTION));
    }

    @Test
    void shouldDetectXSSInHeaderValue() {
        HTTPHeaderValidationPipeline pipeline = new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_VALUE);

        String xssHeader = "text/html; <script>alert('xss')</script>";

        UrlSecurityException exception = assertThrows(UrlSecurityException.class, () ->
                pipeline.validate(xssHeader));

        // This will likely fail at pattern matching stage
        assertEquals(UrlSecurityFailureType.XSS_DETECTED, exception.getFailureType());
        assertEquals(ValidationType.HEADER_VALUE, exception.getValidationType());
        assertEquals(xssHeader, exception.getOriginalInput());

        // Verify event counter was incremented
        assertEquals(1, eventCounter.getCount(UrlSecurityFailureType.XSS_DETECTED));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "Authorization",
            "Content-Type",
            "X-Forwarded-For",
            "User-Agent",
            "Accept",
            "Accept-Language",
            "Cache-Control",
            "X-Custom-Header-Name"
    })
    void shouldAcceptValidHeaderNames(String validHeaderName) throws UrlSecurityException {
        HTTPHeaderValidationPipeline pipeline = new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_NAME);

        String result = pipeline.validate(validHeaderName);
        assertNotNull(result);
        assertEquals(validHeaderName, result);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "application/json",
            "text/html; charset=utf-8",
            "gzip, deflate, br",
            "en-US,en;q=0.9",
            "max-age=3600, must-revalidate",
            "192.168.1.1, 10.0.0.1",
            "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2)"
    })
    void shouldAcceptValidHeaderValues(String validHeaderValue) throws UrlSecurityException {
        HTTPHeaderValidationPipeline pipeline = new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_VALUE);

        String result = pipeline.validate(validHeaderValue);
        assertNotNull(result);
        assertEquals(validHeaderValue, result);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "Bearer token\r\nX-Injected: malicious",     // CRLF injection
            "Bearer token\nX-Injected: malicious",       // LF injection  
            "Bearer token\rX-Injected: malicious",       // CR injection
            "Bearer token\r\n\r\nHTTP/1.1 200 OK",       // HTTP response splitting
            "Bearer token\u0000admin"                     // Null byte injection
    })
    void shouldRejectHeaderInjectionVariants(String maliciousHeader) {
        HTTPHeaderValidationPipeline pipeline = new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_VALUE);

        assertThrows(UrlSecurityException.class, () ->
                pipeline.validate(maliciousHeader));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "Header\rName",       // CR in header name
            "Header\nName",       // LF in header name
            "Header\r\nName",     // CRLF in header name
            "Header\u0000Name"    // Null byte in header name
    })
    void shouldRejectInvalidHeaderNames(String maliciousHeaderName) {
        HTTPHeaderValidationPipeline pipeline = new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_NAME);

        assertThrows(UrlSecurityException.class, () ->
                pipeline.validate(maliciousHeaderName));
    }

    @Test
    void shouldSequentiallyApplyStages() {
        HTTPHeaderValidationPipeline pipeline = new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_VALUE);

        // The pipeline should apply stages in order
        // We can verify this by checking that a header that would fail different stages
        // fails at the first applicable stage
        
        // This header value is too long AND has invalid characters
        // It should fail at length validation first
        String problematicHeader = "Bearer " + "token with\r\ninjection".repeat(1000);

        UrlSecurityException exception = assertThrows(UrlSecurityException.class, () ->
                pipeline.validate(problematicHeader));

        // Should fail at length validation (first stage)
        assertEquals(UrlSecurityFailureType.INPUT_TOO_LONG, exception.getFailureType());
    }

    @Test
    void shouldTrackMultipleSecurityEvents() {
        HTTPHeaderValidationPipeline pipeline = new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_VALUE);

        // Try multiple different attacks
        try {
            pipeline.validate("Bearer token\r\nX-Injected: malicious");
        } catch (UrlSecurityException ignored) {
        }

        try {
            pipeline.validate("Bearer token\u0000admin");
        } catch (UrlSecurityException ignored) {
        }

        try {
            pipeline.validate("<script>alert('xss')</script>");
        } catch (UrlSecurityException ignored) {
        }

        // Verify that security events were tracked
        assertTrue(eventCounter.getTotalCount() > 0,
                "Expected at least one security event to be tracked");

        // Verify null byte injection is tracked (this should work)
        assertEquals(1, eventCounter.getCount(UrlSecurityFailureType.NULL_BYTE_INJECTION));

        // Verify invalid character is tracked (CRLF should be rejected)
        assertEquals(1, eventCounter.getCount(UrlSecurityFailureType.INVALID_CHARACTER));
    }

    @Test
    void shouldHaveCorrectEqualsAndHashCode() {
        HTTPHeaderValidationPipeline pipeline1 = new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_VALUE);
        HTTPHeaderValidationPipeline pipeline2 = new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_VALUE);

        assertEquals(pipeline1, pipeline2);
        assertEquals(pipeline1.hashCode(), pipeline2.hashCode());

        // Different validation types should not be equal
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

        // Verify stages are in the correct order
        var stages = pipeline.getStages();
        assertEquals(4, stages.size()); // No decoding stage for headers

        // Check stage types in order
        assertTrue(stages.getFirst().getClass().getSimpleName().contains("Length"));
        assertTrue(stages.get(1).getClass().getSimpleName().contains("Character"));
        assertTrue(stages.get(2).getClass().getSimpleName().contains("Normalization"));
        assertTrue(stages.get(3).getClass().getSimpleName().contains("Pattern"));
    }

    @Test
    void shouldHandleDifferentValidationTypes() throws UrlSecurityException {
        // Test that pipelines configured for different header types work correctly
        
        HTTPHeaderValidationPipeline namesPipeline = new HTTPHeaderValidationPipeline(
                config, eventCounter, ValidationType.HEADER_NAME);
        HTTPHeaderValidationPipeline valuesPipeline = new HTTPHeaderValidationPipeline(
                config, eventCounter, ValidationType.HEADER_VALUE);

        // Both should handle valid inputs
        String validName = "Authorization";
        String validValue = "Bearer token123";

        assertEquals(validName, namesPipeline.validate(validName));
        assertEquals(validValue, valuesPipeline.validate(validValue));

        // Verify they have different validation types
        assertEquals(ValidationType.HEADER_NAME, namesPipeline.getValidationType());
        assertEquals(ValidationType.HEADER_VALUE, valuesPipeline.getValidationType());
    }

    @Test
    void shouldDetectSQLInjectionInHeaders() {
        HTTPHeaderValidationPipeline pipeline = new HTTPHeaderValidationPipeline(config, eventCounter, ValidationType.HEADER_VALUE);

        String sqlInjectionHeader = "'; DROP TABLE users; --";

        UrlSecurityException exception = assertThrows(UrlSecurityException.class, () ->
                pipeline.validate(sqlInjectionHeader));

        // This will likely fail at pattern matching stage
        assertEquals(UrlSecurityFailureType.SQL_INJECTION_DETECTED, exception.getFailureType());
        assertEquals(ValidationType.HEADER_VALUE, exception.getValidationType());
        assertEquals(sqlInjectionHeader, exception.getOriginalInput());

        // Verify event counter was incremented
        assertEquals(1, eventCounter.getCount(UrlSecurityFailureType.SQL_INJECTION_DETECTED));
    }
}