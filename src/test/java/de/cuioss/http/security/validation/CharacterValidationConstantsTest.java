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

import de.cuioss.http.security.core.ValidationType;
import org.junit.jupiter.api.Test;

import java.util.BitSet;

import static org.junit.jupiter.api.Assertions.*;

class CharacterValidationConstantsTest {

    @Test
    void shouldInitializeRFC3986UnreservedCharacters() {
        BitSet unreserved = CharacterValidationConstants.RFC3986_UNRESERVED;

        // Test ALPHA characters
        for (char c = 'A'; c <= 'Z'; c++) {
            assertTrue(unreserved.get(c), "Uppercase letter " + c + " should be allowed");
        }
        for (char c = 'a'; c <= 'z'; c++) {
            assertTrue(unreserved.get(c), "Lowercase letter " + c + " should be allowed");
        }

        // Test DIGIT characters
        for (char c = '0'; c <= '9'; c++) {
            assertTrue(unreserved.get(c), "Digit " + c + " should be allowed");
        }

        // Test specific unreserved characters
        assertTrue(unreserved.get('-'));
        assertTrue(unreserved.get('.'));
        assertTrue(unreserved.get('_'));
        assertTrue(unreserved.get('~'));

        // Test some characters that should NOT be allowed
        assertFalse(unreserved.get(' '));
        assertFalse(unreserved.get('/'));
        assertFalse(unreserved.get('?'));
        assertFalse(unreserved.get('#'));
    }

    @Test
    void shouldInitializeRFC3986PathCharacters() {
        BitSet pathChars = CharacterValidationConstants.RFC3986_PATH_CHARS;

        // Should include all unreserved characters
        assertTrue(pathChars.get('A'));
        assertTrue(pathChars.get('0'));
        assertTrue(pathChars.get('-'));

        // Should include path-specific characters
        assertTrue(pathChars.get('/'));
        assertTrue(pathChars.get('@'));
        assertTrue(pathChars.get(':'));

        // Should include sub-delims for path
        assertTrue(pathChars.get('!'));
        assertTrue(pathChars.get('$'));
        assertTrue(pathChars.get('&'));
        assertTrue(pathChars.get('\''));
        assertTrue(pathChars.get('('));
        assertTrue(pathChars.get(')'));
        assertTrue(pathChars.get('*'));
        assertTrue(pathChars.get('+'));
        assertTrue(pathChars.get(','));
        assertTrue(pathChars.get(';'));
        assertTrue(pathChars.get('='));

        // Should NOT include some characters
        assertFalse(pathChars.get(' '));
        assertFalse(pathChars.get('?'));
        assertFalse(pathChars.get('#'));
    }

    @Test
    void shouldInitializeRFC3986QueryCharacters() {
        BitSet queryChars = CharacterValidationConstants.RFC3986_QUERY_CHARS;

        // Should include all unreserved characters
        assertTrue(queryChars.get('A'));
        assertTrue(queryChars.get('0'));
        assertTrue(queryChars.get('-'));

        // Should include query-specific characters
        assertTrue(queryChars.get('?'));
        assertTrue(queryChars.get('&'));
        assertTrue(queryChars.get('='));

        // Should include some sub-delims for query
        assertTrue(queryChars.get('!'));
        assertTrue(queryChars.get('$'));
        assertTrue(queryChars.get('\''));

        // Should NOT include some characters
        assertFalse(queryChars.get(' '));
        assertFalse(queryChars.get('#'));
    }

    @Test
    void shouldInitializeRFC7230HeaderCharacters() {
        BitSet headerChars = CharacterValidationConstants.RFC7230_HEADER_CHARS;

        // Should include most visible ASCII
        assertTrue(headerChars.get('A'));
        assertTrue(headerChars.get('0'));
        assertTrue(headerChars.get('-'));
        assertTrue(headerChars.get('_'));
        assertTrue(headerChars.get('/'));
        assertTrue(headerChars.get(':'));
        assertTrue(headerChars.get('='));

        // Should include space and tab
        assertTrue(headerChars.get(' '));
        assertTrue(headerChars.get('\t'));

        // Should exclude control characters
        assertFalse(headerChars.get('\0'));
        assertFalse(headerChars.get('\n'));
        assertFalse(headerChars.get('\r'));
        assertFalse(headerChars.get('\u0001'));

        // Should exclude characters outside printable range
        assertFalse(headerChars.get((char) 127)); // DEL
        assertFalse(headerChars.get((char) 31));  // Below space
    }

    @Test
    void shouldReturnCorrectCharacterSetForValidationType() {
        assertSame(CharacterValidationConstants.RFC3986_PATH_CHARS,
                CharacterValidationConstants.getCharacterSet(ValidationType.URL_PATH));

        assertSame(CharacterValidationConstants.RFC3986_QUERY_CHARS,
                CharacterValidationConstants.getCharacterSet(ValidationType.PARAMETER_NAME));
        assertSame(CharacterValidationConstants.RFC3986_QUERY_CHARS,
                CharacterValidationConstants.getCharacterSet(ValidationType.PARAMETER_VALUE));

        assertSame(CharacterValidationConstants.RFC7230_HEADER_CHARS,
                CharacterValidationConstants.getCharacterSet(ValidationType.HEADER_NAME));
        assertSame(CharacterValidationConstants.RFC7230_HEADER_CHARS,
                CharacterValidationConstants.getCharacterSet(ValidationType.HEADER_VALUE));

        assertSame(CharacterValidationConstants.HTTP_BODY_CHARS,
                CharacterValidationConstants.getCharacterSet(ValidationType.BODY));
        assertSame(CharacterValidationConstants.RFC3986_UNRESERVED,
                CharacterValidationConstants.getCharacterSet(ValidationType.COOKIE_NAME));
        assertSame(CharacterValidationConstants.RFC3986_UNRESERVED,
                CharacterValidationConstants.getCharacterSet(ValidationType.COOKIE_VALUE));
    }

    @Test
    void shouldNotAllowNullValidationType() {
        assertThrows(NullPointerException.class, () ->
                CharacterValidationConstants.getCharacterSet(null));
    }
}