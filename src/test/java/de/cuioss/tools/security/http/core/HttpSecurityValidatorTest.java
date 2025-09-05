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
package de.cuioss.tools.security.http.core;

import de.cuioss.tools.security.http.exceptions.UrlSecurityException;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link HttpSecurityValidator}
 */
class HttpSecurityValidatorTest {

    private static final String TEST_INPUT = "testInput";
    private static final String TEST_OUTPUT = "testOutput";

    @Test
    void shouldBeFunctionalInterface() {
        // Verify it can be used as a lambda
        HttpSecurityValidator validator = input -> input != null ? input.toUpperCase() : "";

        assertEquals("HELLO", validator.validate("hello"));
        assertEquals("", validator.validate(null));
    }

    @Test
    void shouldSupportMethodReference() {
        // Verify it can be used with method references
        HttpSecurityValidator validator = String::toUpperCase;

        assertEquals("HELLO", validator.validate("hello"));
    }

    @Test
    void shouldComposeValidators() {
        HttpSecurityValidator first = input -> input + "_first";
        HttpSecurityValidator second = input -> input + "_second";

        HttpSecurityValidator composed = first.andThen(second);

        assertEquals("test_first_second", composed.validate("test"));
    }

    @Test
    void shouldComposeValidatorsWithCompose() {
        HttpSecurityValidator first = input -> input + "_first";
        HttpSecurityValidator second = input -> input + "_second";

        HttpSecurityValidator composed = second.compose(first);

        assertEquals("test_first_second", composed.validate("test"));
    }

    @Test
    void shouldPropagateExceptionsInComposition() {
        HttpSecurityValidator failing = input -> {
            throw UrlSecurityException.builder()
                    .failureType(UrlSecurityFailureType.INVALID_CHARACTER)
                    .validationType(ValidationType.URL_PATH)
                    .originalInput(input)
                    .build();
        };
        HttpSecurityValidator normal = input -> input + "_processed";

        HttpSecurityValidator composed = failing.andThen(normal);

        UrlSecurityException thrown = assertThrows(UrlSecurityException.class,
                () -> composed.validate("test"));
        assertEquals(UrlSecurityFailureType.INVALID_CHARACTER, thrown.getFailureType());
    }

    @Test
    void shouldRequireNonNullInAndThen() {
        HttpSecurityValidator validator = input -> input;

        NullPointerException thrown = assertThrows(NullPointerException.class,
                () -> validator.andThen(null));
        assertTrue(thrown.getMessage().contains("after validator must not be null"));
    }

    @Test
    void shouldRequireNonNullInCompose() {
        HttpSecurityValidator validator = input -> input;

        NullPointerException thrown = assertThrows(NullPointerException.class,
                () -> validator.compose(null));
        assertTrue(thrown.getMessage().contains("before validator must not be null"));
    }

    @Test
    void shouldSupportConditionalValidation() {
        HttpSecurityValidator validator = input -> input.toUpperCase();
        HttpSecurityValidator conditionalValidator = validator.when(input -> input.startsWith("test"));

        assertEquals("TESTVALUE", conditionalValidator.validate("testValue"));
        assertEquals("otherValue", conditionalValidator.validate("otherValue")); // Unchanged
    }

    @Test
    void shouldRequireNonNullPredicateInWhen() {
        HttpSecurityValidator validator = input -> input;

        NullPointerException thrown = assertThrows(NullPointerException.class,
                () -> validator.when(null));
        assertTrue(thrown.getMessage().contains("predicate must not be null"));
    }

    @Test
    void shouldProvideIdentityValidator() {
        HttpSecurityValidator identity = HttpSecurityValidator.identity();

        assertEquals(TEST_INPUT, identity.validate(TEST_INPUT));
        assertNull(identity.validate(null));
        assertEquals("", identity.validate(""));
    }

    @Test
    void shouldProvideRejectValidator() {
        HttpSecurityValidator rejectValidator = HttpSecurityValidator.reject(
                UrlSecurityFailureType.INVALID_CHARACTER,
                ValidationType.URL_PATH
        );

        UrlSecurityException thrown = assertThrows(UrlSecurityException.class,
                () -> rejectValidator.validate("anything"));

        assertEquals(UrlSecurityFailureType.INVALID_CHARACTER, thrown.getFailureType());
        assertEquals(ValidationType.URL_PATH, thrown.getValidationType());
        assertEquals("anything", thrown.getOriginalInput());
        assertTrue(thrown.getDetail().isPresent());
        assertTrue(thrown.getDetail().get().contains("unconditionally rejected"));
    }

    @Test
    void shouldHandleNullInRejectValidator() {
        HttpSecurityValidator rejectValidator = HttpSecurityValidator.reject(
                UrlSecurityFailureType.INVALID_CHARACTER,
                ValidationType.URL_PATH
        );

        UrlSecurityException thrown = assertThrows(UrlSecurityException.class,
                () -> rejectValidator.validate(null));

        assertEquals("null", thrown.getOriginalInput());
    }

    @Test
    void shouldRequireNonNullParametersInReject() {
        assertThrows(NullPointerException.class, () ->
                HttpSecurityValidator.reject(null, ValidationType.URL_PATH));
        assertThrows(NullPointerException.class, () ->
                HttpSecurityValidator.reject(UrlSecurityFailureType.INVALID_CHARACTER, null));
    }

    @Test
    void shouldSupportComplexComposition() {
        // Create a pipeline: trim -> lowercase -> reject if contains "bad"
        HttpSecurityValidator trimmer = String::trim;
        HttpSecurityValidator lowercaser = String::toLowerCase;
        HttpSecurityValidator badWordRejecter = input -> {
            if (input.contains("bad")) {
                throw UrlSecurityException.builder()
                        .failureType(UrlSecurityFailureType.SUSPICIOUS_PATTERN)
                        .validationType(ValidationType.URL_PATH)
                        .originalInput(input)
                        .build();
            }
            return input;
        };

        HttpSecurityValidator pipeline = trimmer.andThen(lowercaser).andThen(badWordRejecter);

        assertEquals("good", pipeline.validate("  GOOD  "));

        UrlSecurityException thrown = assertThrows(UrlSecurityException.class,
                () -> pipeline.validate("  BAD  "));
        assertEquals("bad", thrown.getOriginalInput()); // Should be the processed input
    }

    @Test
    void shouldSupportConditionalPipeline() {
        HttpSecurityValidator processor = input -> input.toUpperCase();
        HttpSecurityValidator conditionalProcessor = processor.when(input ->
                input != null && input.startsWith("process:"));

        assertEquals("PROCESS:TEST", conditionalProcessor.validate("process:test"));
        assertEquals("skip:test", conditionalProcessor.validate("skip:test"));
        assertNull(conditionalProcessor.validate(null));
    }

    @Test
    void shouldWorkWithStreams() {
        HttpSecurityValidator validator = input -> input != null ? input.trim() : "";

        List<String> inputs = Arrays.asList(" hello ", " world ", null);
        List<String> outputs = inputs.stream()
                .map(validator::validate)
                .collect(Collectors.toList());

        assertEquals(Arrays.asList("hello", "world", ""), outputs);
    }

    @Test
    void shouldPreserveExceptionDetails() {
        String testInput = "dangerous_input";
        String testDetail = "Specific violation details";

        HttpSecurityValidator validator = input -> {
            throw UrlSecurityException.builder()
                    .failureType(UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED)
                    .validationType(ValidationType.URL_PATH)
                    .originalInput(input)
                    .detail(testDetail)
                    .build();
        };

        UrlSecurityException thrown = assertThrows(UrlSecurityException.class,
                () -> validator.validate(testInput));

        assertEquals(testInput, thrown.getOriginalInput());
        assertTrue(thrown.getDetail().isPresent());
        assertEquals(testDetail, thrown.getDetail().get());
        assertEquals(UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED, thrown.getFailureType());
        assertEquals(ValidationType.URL_PATH, thrown.getValidationType());
    }

    @Test
    void shouldSupportNestedComposition() {
        HttpSecurityValidator a = input -> input + "A";
        HttpSecurityValidator b = input -> input + "B";
        HttpSecurityValidator c = input -> input + "C";

        // Test ((a andThen b) andThen c)
        HttpSecurityValidator nested1 = a.andThen(b).andThen(c);
        assertEquals("testABC", nested1.validate("test"));

        // Test (a andThen (b andThen c))
        HttpSecurityValidator nested2 = a.andThen(b.andThen(c));
        assertEquals("testABC", nested2.validate("test"));

        // Both should produce the same result
        assertEquals(nested1.validate("test"), nested2.validate("test"));
    }

    @Test
    void shouldHandleEmptyAndSpecialStrings() {
        HttpSecurityValidator validator = HttpSecurityValidator.identity();

        assertEquals("", validator.validate(""));
        assertEquals(" ", validator.validate(" "));
        assertEquals("\n", validator.validate("\n"));
        assertEquals("\t", validator.validate("\t"));
        assertEquals("🚀", validator.validate("🚀")); // Unicode
    }
}