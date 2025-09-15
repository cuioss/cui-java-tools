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
package de.cuioss.http.security.validation;

import de.cuioss.http.security.config.SecurityConfiguration;
import de.cuioss.http.security.core.UrlSecurityFailureType;
import de.cuioss.http.security.core.ValidationType;
import de.cuioss.http.security.exceptions.UrlSecurityException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive tests for {@link NormalizationStage}.
 *
 * <p>This test class validates RFC 3986 compliance, security protections,
 * and edge case handling for path normalization operations.</p>
 */
class NormalizationStageTest {

    private NormalizationStage stage;
    private SecurityConfiguration config;

    @BeforeEach
    void setUp() {
        config = SecurityConfiguration.defaults();
        stage = new NormalizationStage(config, ValidationType.URL_PATH);
    }

    @Test
    void validate_withNullInput_returnsNull() {
        assertNull(stage.validate(null));
    }

    @Test
    void validate_withEmptyInput_returnsEmpty() {
        assertEquals("", stage.validate(""));
    }

    /**
     * Test RFC 3986 Section 5.2.4 compliance for legitimate path normalization.
     */
    @ParameterizedTest
    @CsvSource({
            "'/api/users', '/api/users'",
            "'/api/users/', '/api/users/'",
            "'/api/./users', '/api/users'",
            "'/api/users/.', '/api/users'",
            "'/api/users/./data', '/api/users/data'",
            "'/api/users/../admin', '/api/admin'",
            "'/api/users/123/../456', '/api/users/456'",
            "'/api/./users/../admin/./data', '/api/admin/data'",
            "'./relative/path', 'relative/path'",
            "'./relative/../other', 'other'",
            "'path/./to/./resource', 'path/to/resource'",
            "'path/../other/../final', 'final'"
    })
    void validate_withLegitimatePatterns_normalizesCorrectly(String input, String expected) {
        assertEquals(expected, stage.validate(input));
    }

    /**
     * Test normalization preserves important path characteristics.
     */
    @Test
    void validate_preservesLeadingSlash() {
        assertEquals("/normalized", stage.validate("/./normalized"));
        assertEquals("normalized", stage.validate("./normalized"));
    }

    @Test
    void validate_preservesTrailingSlash() {
        assertEquals("/api/users/", stage.validate("/api/users/./"));
        assertEquals("/api/users/", stage.validate("/api/./users/../users/"));
    }

    @Test
    void validate_handlesMultipleConsecutiveSlashes() {
        // Empty segments from double slashes are normalized (RFC compliant)
        assertEquals("/api/users", stage.validate("//api//users"));
        assertEquals("/api/users/", stage.validate("/api//users/"));
    }

    /**
     * Test path traversal attack detection.
     */
    @ParameterizedTest
    @ValueSource(strings = {
            "../../../etc/passwd",
            "../admin",
            "../../secret"
    })
    void validate_withDirectoryEscapeAttempt_throwsException(String input) {
        UrlSecurityException exception = assertThrows(UrlSecurityException.class, () -> stage.validate(input));
        assertEquals(UrlSecurityFailureType.DIRECTORY_ESCAPE_ATTEMPT, exception.getFailureType());
        assertEquals(ValidationType.URL_PATH, exception.getValidationType());
        assertEquals(input, exception.getOriginalInput());
        assertTrue(exception.getDetail().isPresent());
    }

    @Test
    void validate_withAbsolutePathEscape_normalizesCorrectly() {
        // This should normalize to "/etc/passwd" (not throw) since it's a valid absolute path after normalization
        String result = stage.validate("/api/../../../etc/passwd");
        assertEquals("/etc/passwd", result);
    }

    /**
     * Test detection of remaining path traversal patterns after normalization.
     */
    @Test
    void validate_withRemainingTraversalPatterns_throwsException() {
        // This path will normalize to "../still/here" and then be detected as escape
        String pathWithTraversal = "../still/here";
        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> stage.validate(pathWithTraversal));
        assertEquals(UrlSecurityFailureType.DIRECTORY_ESCAPE_ATTEMPT, exception.getFailureType());
    }

    /**
     * Test DoS protection against excessive path segments.
     */
    @Test
    void validate_withExcessiveSegments_throwsException() {
        // Create a path with more than MAX_PATH_SEGMENTS (1000) segments
        StringBuilder pathBuilder = new StringBuilder("/");
        for (int i = 0; i < 1001; i++) {
            pathBuilder.append("seg").append(i).append("/");
        }
        String excessivePath = pathBuilder.toString();

        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> stage.validate(excessivePath));
        assertEquals(UrlSecurityFailureType.EXCESSIVE_NESTING, exception.getFailureType());
        assertEquals(ValidationType.URL_PATH, exception.getValidationType());
        assertEquals(excessivePath, exception.getOriginalInput());
        assertTrue(exception.getDetail().isPresent());
        assertTrue(exception.getDetail().get().contains("too many segments"));
    }

    /**
     * Test DoS protection against excessive directory depth.
     */
    @Test
    void validate_withExcessiveDepth_throwsException() {
        // Create a path with more than MAX_DIRECTORY_DEPTH (100) levels
        StringBuilder pathBuilder = new StringBuilder("/");
        for (int i = 0; i < 101; i++) {
            pathBuilder.append("level").append(i).append("/");
        }
        String deepPath = pathBuilder.toString();

        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> stage.validate(deepPath));
        assertEquals(UrlSecurityFailureType.EXCESSIVE_NESTING, exception.getFailureType());
        assertTrue(exception.getDetail().isPresent());
        assertTrue(exception.getDetail().get().contains("depth"));
        assertTrue(exception.getDetail().get().contains("exceeds maximum"));
    }

    /**
     * Test edge cases with complex combinations of dot segments.
     */
    @ParameterizedTest
    @CsvSource({
            "'./././api/users', 'api/users'",
            "'/./././api/users', '/api/users'",
            "'/api/././users/././data', '/api/users/data'",
            "'/../../../still/valid', '/still/valid'"
    })
    void validate_withComplexDotPatterns_handlesCorrectly(String input, String expected) {
        assertEquals(expected, stage.validate(input));
    }

    /**
     * Test Windows-style path separators are handled correctly.
     */
    @Test
    void validate_withWindowsSeparators_detectsEscape() {
        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> stage.validate("..\\windows\\path"));
        // This will be detected as directory escape since it starts with ..
        assertEquals(UrlSecurityFailureType.DIRECTORY_ESCAPE_ATTEMPT, exception.getFailureType());
    }

    /**
     * Test conditional validation with when() method.
     */
    @Test
    void when_withCondition_appliesConditionally() {
        var conditionalValidator = stage.when(input -> input != null && input.startsWith("/api"));

        // Should normalize when condition is true
        assertEquals("/api/users", conditionalValidator.validate("/api/./users"));

        // Should skip validation when condition is false
        assertEquals("other/./path", conditionalValidator.validate("other/./path"));
    }

    /**
     * Test that the stage correctly reports its configuration.
     */
    @Test
    void toString_includesCorrectInformation() {
        String stringRepresentation = stage.toString();
        assertTrue(stringRepresentation.contains("NormalizationStage"));
        assertTrue(stringRepresentation.contains("URL_PATH"));
        assertTrue(stringRepresentation.contains("maxSegments=1000"));
        assertTrue(stringRepresentation.contains("maxDepth=100"));
    }

    /**
     * Test that validation type is correctly preserved in exceptions.
     */
    @Test
    void validate_preservesValidationType() {
        NormalizationStage parameterStage = new NormalizationStage(config, ValidationType.PARAMETER_NAME);

        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> parameterStage.validate("../escape"));
        assertEquals(ValidationType.PARAMETER_NAME, exception.getValidationType());
    }

    /**
     * Test performance with realistic path lengths.
     */
    @Test
    void validate_withRealisticPath_performsWell() {
        // Create a realistic deeply nested path that's still within limits
        StringBuilder pathBuilder = new StringBuilder("/app/modules");
        for (int i = 0; i < 50; i++) {  // Well within the 100 depth limit
            pathBuilder.append("/module").append(i);
        }
        pathBuilder.append("/./final/../resource");

        String complexPath = pathBuilder.toString();
        String result = stage.validate(complexPath);

        // Should normalize correctly
        assertNotNull(result);
        assertFalse(result.contains("./"));
        assertFalse(result.contains("../"));
    }

    /**
     * Test proper handling of root path.
     */
    @ParameterizedTest
    @CsvSource({
            "'/', '/'",
            "'/./././', '/'",
            "'/.', '/'",
            "'/../', '/'"  // This goes above root but is normalized to root
    })
    void validate_withRootPaths_handlesCorrectly(String input, String expected) {
        assertEquals(expected, stage.validate(input));
    }

    /**
     * Test that original input is preserved in exception details.
     */
    @Test
    void validate_withSecurityViolation_preservesOriginalInput() {
        String maliciousInput = "../../../etc/passwd";

        UrlSecurityException exception = assertThrows(UrlSecurityException.class,
                () -> stage.validate(maliciousInput));

        assertEquals(maliciousInput, exception.getOriginalInput());
        assertNotNull(exception.getSanitizedInput());
        assertNotEquals(maliciousInput, exception.getSanitizedInput());
    }
}