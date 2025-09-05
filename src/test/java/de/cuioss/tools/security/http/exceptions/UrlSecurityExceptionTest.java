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
package de.cuioss.tools.security.http.exceptions;

import de.cuioss.tools.security.http.core.UrlSecurityFailureType;
import de.cuioss.tools.security.http.core.ValidationType;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link UrlSecurityException}
 */
class UrlSecurityExceptionTest {

    private static final UrlSecurityFailureType TEST_FAILURE_TYPE = UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED;
    private static final ValidationType TEST_VALIDATION_TYPE = ValidationType.URL_PATH;
    private static final String TEST_INPUT = "../../../etc/passwd";
    private static final String TEST_SANITIZED = "etc/passwd";
    private static final String TEST_DETAIL = "Path traversal attempt detected";

    @Test
    void shouldCreateBuilderInstance() {
        UrlSecurityException.Builder builder = UrlSecurityException.builder();
        assertNotNull(builder);
    }

    @Test
    void shouldBuildMinimalException() {
        UrlSecurityException exception = UrlSecurityException.builder()
                .failureType(TEST_FAILURE_TYPE)
                .validationType(TEST_VALIDATION_TYPE)
                .originalInput(TEST_INPUT)
                .build();

        assertEquals(TEST_FAILURE_TYPE, exception.getFailureType());
        assertEquals(TEST_VALIDATION_TYPE, exception.getValidationType());
        assertEquals(TEST_INPUT, exception.getOriginalInput());
        assertTrue(exception.getSanitizedInput().isEmpty());
        assertTrue(exception.getDetail().isEmpty());
        assertNull(exception.getCause());
    }

    @Test
    void shouldBuildFullException() {
        Throwable cause = /*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*/new RuntimeException("Root cause");

        UrlSecurityException exception = UrlSecurityException.builder()
                .failureType(TEST_FAILURE_TYPE)
                .validationType(TEST_VALIDATION_TYPE)
                .originalInput(TEST_INPUT)
                .sanitizedInput(TEST_SANITIZED)
                .detail(TEST_DETAIL)
                .cause(cause)
                .build();

        assertEquals(TEST_FAILURE_TYPE, exception.getFailureType());
        assertEquals(TEST_VALIDATION_TYPE, exception.getValidationType());
        assertEquals(TEST_INPUT, exception.getOriginalInput());
        assertTrue(exception.getSanitizedInput().isPresent());
        assertEquals(TEST_SANITIZED, exception.getSanitizedInput().get());
        assertTrue(exception.getDetail().isPresent());
        assertEquals(TEST_DETAIL, exception.getDetail().get());
        assertEquals(cause, exception.getCause());
    }

    @Test
    void shouldRequireFailureType() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () ->
                UrlSecurityException.builder()
                        .validationType(TEST_VALIDATION_TYPE)
                        .originalInput(TEST_INPUT)
                        .build());

        assertTrue(thrown.getMessage().contains("failureType must be set"));
    }

    @Test
    void shouldRequireValidationType() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () ->
                UrlSecurityException.builder()
                        .failureType(TEST_FAILURE_TYPE)
                        .originalInput(TEST_INPUT)
                        .build());

        assertTrue(thrown.getMessage().contains("validationType must be set"));
    }

    @Test
    void shouldRequireOriginalInput() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () ->
                UrlSecurityException.builder()
                        .failureType(TEST_FAILURE_TYPE)
                        .validationType(TEST_VALIDATION_TYPE)
                        .build());

        assertTrue(thrown.getMessage().contains("originalInput must be set"));
    }

    @Test
    void shouldSupportFluentBuilding() {
        UrlSecurityException exception = UrlSecurityException.builder()
                .failureType(TEST_FAILURE_TYPE)
                .validationType(TEST_VALIDATION_TYPE)
                .originalInput(TEST_INPUT)
                .sanitizedInput(TEST_SANITIZED)
                .detail(TEST_DETAIL)
                .cause(/*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*/new RuntimeException())
                .build();

        assertNotNull(exception);
    }

    @Test
    void shouldGenerateDescriptiveMessage() {
        UrlSecurityException exception = UrlSecurityException.builder()
                .failureType(TEST_FAILURE_TYPE)
                .validationType(TEST_VALIDATION_TYPE)
                .originalInput(TEST_INPUT)
                .build();

        String message = exception.getMessage();
        assertNotNull(message);
        assertTrue(message.contains(TEST_VALIDATION_TYPE.toString()));
        assertTrue(message.contains(TEST_FAILURE_TYPE.getDescription()));
        assertTrue(message.contains(TEST_INPUT));
    }

    @Test
    void shouldGenerateMessageWithDetail() {
        UrlSecurityException exception = UrlSecurityException.builder()
                .failureType(TEST_FAILURE_TYPE)
                .validationType(TEST_VALIDATION_TYPE)
                .originalInput(TEST_INPUT)
                .detail(TEST_DETAIL)
                .build();

        String message = exception.getMessage();
        assertTrue(message.contains(TEST_DETAIL));
    }

    @Test
    void shouldTruncateLongInputInMessage() {
        String longInput = "A".repeat(300); // Very long input
        
        UrlSecurityException exception = UrlSecurityException.builder()
                .failureType(TEST_FAILURE_TYPE)
                .validationType(TEST_VALIDATION_TYPE)
                .originalInput(longInput)
                .build();

        String message = exception.getMessage();
        assertNotNull(message);
        assertFalse(message.contains("A".repeat(300))); // Should be truncated
        assertTrue(message.contains("...")); // Should show truncation
    }

    @Test
    void shouldSanitizeControlCharactersInMessage() {
        String inputWithControlChars = "test\r\n\ttab\u0000null";

        UrlSecurityException exception = UrlSecurityException.builder()
                .failureType(UrlSecurityFailureType.CONTROL_CHARACTERS)
                .validationType(TEST_VALIDATION_TYPE)
                .originalInput(inputWithControlChars)
                .build();

        String message = exception.getMessage();
        assertNotNull(message);
        assertFalse(message.contains("\r"));
        assertFalse(message.contains("\n"));
        assertFalse(message.contains("\t"));
        assertFalse(message.contains("\u0000"));
        assertTrue(message.contains("?")); // Control chars should be replaced
    }

    @Test
    void shouldHandleNullInputSafely() {
        // This should not happen in normal usage, but test defensive behavior
        String nullInput = null;

        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () ->
                UrlSecurityException.builder()
                        .failureType(TEST_FAILURE_TYPE)
                        .validationType(TEST_VALIDATION_TYPE)
                        .originalInput(nullInput)
                        .build());

        assertTrue(thrown.getMessage().contains("originalInput must be set"));
    }

    @Test
    void shouldSupportEqualsAndHashCode() {
        UrlSecurityException exception1 = UrlSecurityException.builder()
                .failureType(TEST_FAILURE_TYPE)
                .validationType(TEST_VALIDATION_TYPE)
                .originalInput(TEST_INPUT)
                .sanitizedInput(TEST_SANITIZED)
                .detail(TEST_DETAIL)
                .build();

        UrlSecurityException exception2 = UrlSecurityException.builder()
                .failureType(TEST_FAILURE_TYPE)
                .validationType(TEST_VALIDATION_TYPE)
                .originalInput(TEST_INPUT)
                .sanitizedInput(TEST_SANITIZED)
                .detail(TEST_DETAIL)
                .build();

        assertEquals(exception1, exception2);
        assertEquals(exception1.hashCode(), exception2.hashCode());
    }

    @Test
    void shouldNotEqualDifferentExceptions() {
        UrlSecurityException exception1 = UrlSecurityException.builder()
                .failureType(TEST_FAILURE_TYPE)
                .validationType(TEST_VALIDATION_TYPE)
                .originalInput(TEST_INPUT)
                .build();

        UrlSecurityException exception2 = UrlSecurityException.builder()
                .failureType(UrlSecurityFailureType.INVALID_ENCODING)
                .validationType(TEST_VALIDATION_TYPE)
                .originalInput(TEST_INPUT)
                .build();

        assertNotEquals(exception1, exception2);
        assertNotEquals(exception1.hashCode(), exception2.hashCode());
    }

    @Test
    void shouldSupportToString() {
        UrlSecurityException exception = UrlSecurityException.builder()
                .failureType(TEST_FAILURE_TYPE)
                .validationType(TEST_VALIDATION_TYPE)
                .originalInput(TEST_INPUT)
                .sanitizedInput(TEST_SANITIZED)
                .detail(TEST_DETAIL)
                .build();

        String toString = exception.toString();
        assertNotNull(toString);
        assertTrue(toString.contains("UrlSecurityException"));
        assertTrue(toString.contains(TEST_FAILURE_TYPE.toString()));
        assertTrue(toString.contains(TEST_VALIDATION_TYPE.toString()));
        assertTrue(toString.contains(TEST_DETAIL));
    }

    @Test
    void shouldTruncateInputInToString() {
        String longInput = "A".repeat(300);

        UrlSecurityException exception = UrlSecurityException.builder()
                .failureType(TEST_FAILURE_TYPE)
                .validationType(TEST_VALIDATION_TYPE)
                .originalInput(longInput)
                .build();

        String toString = exception.toString();
        assertFalse(toString.contains("A".repeat(300))); // Should be truncated
        assertTrue(toString.contains("...")); // Should show truncation
    }

    @Test
    void shouldExtendRuntimeException() {
        UrlSecurityException exception = UrlSecurityException.builder()
                .failureType(TEST_FAILURE_TYPE)
                .validationType(TEST_VALIDATION_TYPE)
                .originalInput(TEST_INPUT)
                .build();

        assertTrue(exception instanceof RuntimeException);
        assertTrue(exception instanceof Exception);
        assertTrue(exception instanceof Throwable);
    }

    @Test
    void shouldSupportCauseChaining() {
        RuntimeException rootCause = /*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*/new RuntimeException("Root cause");

        UrlSecurityException exception = UrlSecurityException.builder()
                .failureType(TEST_FAILURE_TYPE)
                .validationType(TEST_VALIDATION_TYPE)
                .originalInput(TEST_INPUT)
                .cause(rootCause)
                .build();

        assertEquals(rootCause, exception.getCause());

        // Test chaining
        try {
            throw exception;
        } catch (UrlSecurityException caught) {
            assertEquals(rootCause, caught.getCause());
        }
    }

    @Test
    void shouldHandleEmptyStrings() {
        UrlSecurityException exception = UrlSecurityException.builder()
                .failureType(TEST_FAILURE_TYPE)
                .validationType(TEST_VALIDATION_TYPE)
                .originalInput("")
                .sanitizedInput("")
                .detail("")
                .build();

        assertEquals("", exception.getOriginalInput());
        assertEquals("", exception.getSanitizedInput().orElse(null));
        assertEquals("", exception.getDetail().orElse(null));
    }

    @Test
    void shouldHandleWhitespaceInDetail() {
        UrlSecurityException exception = UrlSecurityException.builder()
                .failureType(TEST_FAILURE_TYPE)
                .validationType(TEST_VALIDATION_TYPE)
                .originalInput(TEST_INPUT)
                .detail("   ")  // Only whitespace
                .build();

        String message = exception.getMessage();
        // Whitespace-only detail should not appear in message
        assertFalse(message.contains(" -    "));
    }

    @Test
    void shouldSupportMethodChaining() {
        // Verify that all builder methods return the builder for chaining
        UrlSecurityException.Builder builder = UrlSecurityException.builder();

        assertSame(builder.getClass(),
                builder.failureType(TEST_FAILURE_TYPE).getClass());
        assertSame(builder.getClass(),
                builder.validationType(TEST_VALIDATION_TYPE).getClass());
        assertSame(builder.getClass(),
                builder.originalInput(TEST_INPUT).getClass());
        assertSame(builder.getClass(),
                builder.sanitizedInput(TEST_SANITIZED).getClass());
        assertSame(builder.getClass(),
                builder.detail(TEST_DETAIL).getClass());
        assertSame(builder.getClass(),
                builder.cause(/*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*//*~~(Use specific not RuntimeException)~~>*/new RuntimeException()).getClass());
    }

    @Test
    void shouldBeImmutableAfterConstruction() {
        UrlSecurityException exception = UrlSecurityException.builder()
                .failureType(TEST_FAILURE_TYPE)
                .validationType(TEST_VALIDATION_TYPE)
                .originalInput(TEST_INPUT)
                .sanitizedInput(TEST_SANITIZED)
                .detail(TEST_DETAIL)
                .build();

        // All getter methods should return the same values
        assertEquals(TEST_FAILURE_TYPE, exception.getFailureType());
        assertEquals(TEST_VALIDATION_TYPE, exception.getValidationType());
        assertEquals(TEST_INPUT, exception.getOriginalInput());
        assertTrue(exception.getSanitizedInput().isPresent());
        assertEquals(TEST_SANITIZED, exception.getSanitizedInput().get());
        assertTrue(exception.getDetail().isPresent());
        assertEquals(TEST_DETAIL, exception.getDetail().get());

        // Values should be consistent across calls
        assertSame(exception.getFailureType(), exception.getFailureType());
        assertSame(exception.getValidationType(), exception.getValidationType());
        assertSame(exception.getOriginalInput(), exception.getOriginalInput());
    }

    @Test
    void shouldGenerateConsistentMessages() {
        UrlSecurityException exception = UrlSecurityException.builder()
                .failureType(TEST_FAILURE_TYPE)
                .validationType(TEST_VALIDATION_TYPE)
                .originalInput(TEST_INPUT)
                .detail(TEST_DETAIL)
                .build();

        String message1 = exception.getMessage();
        String message2 = exception.getMessage();

        assertEquals(message1, message2);
    }
}