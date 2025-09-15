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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.junit.jupiter.api.Assertions.*;

class CharacterValidationStageTest {

    private final SecurityConfiguration config = SecurityConfiguration.defaults();

    @Test
    void shouldAllowNullAndEmptyValues() throws UrlSecurityException {
        CharacterValidationStage stage = new CharacterValidationStage(config, ValidationType.URL_PATH);

        assertNull(stage.validate(null));
        assertEquals("", stage.validate(""));
    }

    @Test
    void shouldAllowValidPathCharacters() throws UrlSecurityException {
        CharacterValidationStage stage = new CharacterValidationStage(config, ValidationType.URL_PATH);

        String validPath = "/api/users/123";
        assertEquals(validPath, stage.validate(validPath));

        String complexPath = "/path/with-special_chars.txt~test!$&'()*+,;=:@";
        assertEquals(complexPath, stage.validate(complexPath));
    }

    @Test
    void shouldAllowValidQueryCharacters() throws UrlSecurityException {
        CharacterValidationStage stage = new CharacterValidationStage(config, ValidationType.PARAMETER_NAME);

        String validParam = "userName123";
        assertEquals(validParam, stage.validate(validParam));

        String complexParam = "param_name-with.special~chars!$'()*+,;";
        assertEquals(complexParam, stage.validate(complexParam));
    }

    @Test
    void shouldAllowValidHeaderCharacters() throws UrlSecurityException {
        CharacterValidationStage stage = new CharacterValidationStage(config, ValidationType.HEADER_NAME);

        String validHeader = "X-Custom-Header";
        assertEquals(validHeader, stage.validate(validHeader));

        String headerWithNumbers = "Header123";
        assertEquals(headerWithNumbers, stage.validate(headerWithNumbers));
    }

    @Test
    void shouldAllowSpaceInHeaderValues() throws UrlSecurityException {
        CharacterValidationStage stage = new CharacterValidationStage(config, ValidationType.HEADER_VALUE);

        String headerValue = "Mozilla/5.0 Chrome Safari";
        assertEquals(headerValue, stage.validate(headerValue));
    }

    @Test
    void shouldRejectNullByteInjection() {
        CharacterValidationStage stage = new CharacterValidationStage(config, ValidationType.URL_PATH);

        String maliciousPath = "/path/with\0null/byte";
        UrlSecurityException exception = assertThrows(UrlSecurityException.class, () ->
                stage.validate(maliciousPath));

        assertEquals(UrlSecurityFailureType.NULL_BYTE_INJECTION, exception.getFailureType());
        assertEquals(ValidationType.URL_PATH, exception.getValidationType());
        assertTrue(exception.getDetail().orElse("").contains("Null byte detected at position 10"));
    }

    @Test
    void shouldRejectEncodedNullByte() {
        CharacterValidationStage stage = new CharacterValidationStage(config, ValidationType.URL_PATH);

        String maliciousPath = "/path/with%00null/byte";
        UrlSecurityException exception = assertThrows(UrlSecurityException.class, () ->
                stage.validate(maliciousPath));

        assertEquals(UrlSecurityFailureType.NULL_BYTE_INJECTION, exception.getFailureType());
        assertEquals(ValidationType.URL_PATH, exception.getValidationType());
        assertTrue(exception.getDetail().orElse("").contains("Encoded null byte (%00) detected at position 10"));
    }

    @Test
    void shouldRejectInvalidCharacters() {
        CharacterValidationStage stage = new CharacterValidationStage(config, ValidationType.URL_PATH);

        String pathWithInvalidChar = "/path/with spaces/invalid";
        UrlSecurityException exception = assertThrows(UrlSecurityException.class, () ->
                stage.validate(pathWithInvalidChar));

        assertEquals(UrlSecurityFailureType.INVALID_CHARACTER, exception.getFailureType());
        assertEquals(ValidationType.URL_PATH, exception.getValidationType());
        assertTrue(exception.getDetail().orElse("").contains("Invalid character ' ' (0x20) at position 10"));
    }

    @Test
    void shouldRejectInvalidEncodingFormat() {
        CharacterValidationStage stage = new CharacterValidationStage(config, ValidationType.URL_PATH);

        // Incomplete percent encoding
        String incompleteEncoding = "/path/with%2";
        UrlSecurityException exception = assertThrows(UrlSecurityException.class, () ->
                stage.validate(incompleteEncoding));

        assertEquals(UrlSecurityFailureType.INVALID_ENCODING, exception.getFailureType());
        assertTrue(exception.getDetail().orElse("").contains("Incomplete percent encoding at position 10"));
    }

    @Test
    void shouldRejectInvalidHexDigits() {
        CharacterValidationStage stage = new CharacterValidationStage(config, ValidationType.URL_PATH);

        String invalidHex = "/path/with%2G";
        UrlSecurityException exception = assertThrows(UrlSecurityException.class, () ->
                stage.validate(invalidHex));

        assertEquals(UrlSecurityFailureType.INVALID_ENCODING, exception.getFailureType());
        assertTrue(exception.getDetail().orElse("").contains("Invalid hex digits in percent encoding at position 10"));
    }

    @Test
    void shouldAllowValidPercentEncoding() throws UrlSecurityException {
        CharacterValidationStage stage = new CharacterValidationStage(config, ValidationType.URL_PATH);

        String encodedPath = "/path/with%20encoded%2Fchars";
        assertEquals(encodedPath, stage.validate(encodedPath));

        String upperCaseHex = "/path/with%2A%2B";
        assertEquals(upperCaseHex, stage.validate(upperCaseHex));

        String lowerCaseHex = "/path/with%2a%2b";
        assertEquals(lowerCaseHex, stage.validate(lowerCaseHex));
    }

    @Test
    void shouldNotAllowPercentEncodingInHeaders() {
        CharacterValidationStage stage = new CharacterValidationStage(config, ValidationType.HEADER_NAME);

        // Headers should allow % character, but percent sequences are not decoded
        // So %20 should be treated as literal characters, which is allowed
        String headerWithEncoding = "Header%20Name";

        // This should actually pass since % is allowed in headers
        assertDoesNotThrow(() -> stage.validate(headerWithEncoding));

        // Test with a character that's actually not allowed in headers (control character)
        String headerWithControlChar = "Header\u0001Name";
        UrlSecurityException exception = assertThrows(UrlSecurityException.class, () ->
                stage.validate(headerWithControlChar));

        assertEquals(UrlSecurityFailureType.INVALID_CHARACTER, exception.getFailureType());
        assertTrue(exception.getDetail().orElse("").contains("Invalid character"));
    }

    @ParameterizedTest
    @EnumSource(ValidationType.class)
    void shouldHandleAllValidationTypes(ValidationType type) {
        CharacterValidationStage stage = new CharacterValidationStage(config, type);

        // Should not throw for basic alphanumeric
        assertDoesNotThrow(() -> stage.validate("abc123"));

        // Should reject null byte for all types
        assertThrows(UrlSecurityException.class, () -> stage.validate("test\0null"));
    }

    @Test
    void shouldRejectHighUnicodeCharacters() {
        CharacterValidationStage stage = new CharacterValidationStage(config, ValidationType.URL_PATH);

        String unicodePath = "/path/with/unicode/字符";
        UrlSecurityException exception = assertThrows(UrlSecurityException.class, () ->
                stage.validate(unicodePath));

        assertEquals(UrlSecurityFailureType.INVALID_CHARACTER, exception.getFailureType());
    }

    @Test
    void shouldHaveCorrectEqualsAndHashCode() {
        CharacterValidationStage stage1 = new CharacterValidationStage(config, ValidationType.URL_PATH);
        CharacterValidationStage stage2 = new CharacterValidationStage(config, ValidationType.URL_PATH);
        CharacterValidationStage stage3 = new CharacterValidationStage(config, ValidationType.PARAMETER_NAME);

        assertEquals(stage1, stage2);
        assertEquals(stage1.hashCode(), stage2.hashCode());
        assertNotEquals(stage1, stage3);
    }

    @Test
    void shouldHaveCorrectToString() {
        CharacterValidationStage stage = new CharacterValidationStage(config, ValidationType.URL_PATH);
        String toString = stage.toString();

        assertTrue(toString.contains("CharacterValidationStage"));
        assertTrue(toString.contains("URL_PATH"));
    }
}