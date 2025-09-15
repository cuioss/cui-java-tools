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

import java.util.BitSet;

/**
 * Pre-computed character sets for validation according to RFC specifications.
 * These BitSets are read-only after initialization and thread-safe for concurrent reads.
 * Implemented by: Task V5
 */
public final class CharacterValidationConstants {

    private CharacterValidationConstants() {
        // Utility class
    }

    // RFC 3986 unreserved characters: ALPHA / DIGIT / "-" / "." / "_" / "~"
    public static final BitSet RFC3986_UNRESERVED;

    // RFC 3986 path characters including unreserved + path-specific
    public static final BitSet RFC3986_PATH_CHARS;

    // RFC 3986 query characters including unreserved + query-specific
    public static final BitSet RFC3986_QUERY_CHARS;

    // RFC 7230 header field characters (visible ASCII minus delimiters)
    public static final BitSet RFC7230_HEADER_CHARS;

    // HTTP body content characters (very permissive for JSON, XML, text, etc.)
    public static final BitSet HTTP_BODY_CHARS;

    static {
        // Initialize RFC3986_UNRESERVED
        BitSet unreserved = new BitSet(256);
        // ALPHA
        for (int i = 'A'; i <= 'Z'; i++) unreserved.set(i);
        for (int i = 'a'; i <= 'z'; i++) unreserved.set(i);
        // DIGIT
        for (int i = '0'; i <= '9'; i++) unreserved.set(i);
        // "-" / "." / "_" / "~"
        unreserved.set('-');
        unreserved.set('.');
        unreserved.set('_');
        unreserved.set('~');
        RFC3986_UNRESERVED = unreserved;

        // Initialize RFC3986_PATH_CHARS
        BitSet pathChars = new BitSet(256);
        pathChars.or(unreserved);  // Include all unreserved chars
        pathChars.set('/');
        pathChars.set('@');
        pathChars.set(':');
        // sub-delims for path: "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
        "!$&'()*+,;=".chars().forEach(pathChars::set);
        RFC3986_PATH_CHARS = pathChars;

        // Initialize RFC3986_QUERY_CHARS
        BitSet queryChars = new BitSet(256);
        queryChars.or(unreserved);  // Include all unreserved chars
        queryChars.set('?');
        queryChars.set('&');
        queryChars.set('=');
        // sub-delims for query
        "!$'()*+,;".chars().forEach(queryChars::set);
        RFC3986_QUERY_CHARS = queryChars;

        // Initialize RFC7230_HEADER_CHARS
        BitSet headerChars = new BitSet(256);
        // RFC 7230: For header values, allow most visible ASCII plus space and tab
        // Only exclude control chars and characters that could break HTTP parsing
        for (int i = 32; i <= 126; i++) { // Include space (32) through tilde (126)
            headerChars.set(i);
        }
        headerChars.set('\t'); // Tab is allowed in headers
        // Only exclude characters that could break HTTP: CR, LF, NULL
        // Note: Other dangerous chars are handled at application level
        RFC7230_HEADER_CHARS = headerChars;

        // Initialize HTTP_BODY_CHARS (very permissive for body content)
        BitSet bodyChars = new BitSet(256);
        // Allow all printable ASCII and extended characters
        for (int i = 32; i <= 126; i++) { // ASCII printable characters
            bodyChars.set(i);
        }
        // Allow common whitespace characters
        bodyChars.set('\t');  // Tab (0x09)
        bodyChars.set('\n');  // Line feed (0x0A)
        bodyChars.set('\r');  // Carriage return (0x0D)
        // Allow extended ASCII and Unicode range (128-255)
        for (int i = 128; i <= 255; i++) {
            bodyChars.set(i);
        }
        // Note: Null bytes and other control chars (1-31) are excluded by default
        // They can be allowed via configuration if needed
        HTTP_BODY_CHARS = bodyChars;
    }

    /**
     * Returns the character set for the given validation type.
     * Note: Returns the actual BitSet, not a copy. Do not modify!
     */
    public static BitSet getCharacterSet(ValidationType type) {
        return switch (type) {
            case URL_PATH -> RFC3986_PATH_CHARS;
            case PARAMETER_NAME, PARAMETER_VALUE -> RFC3986_QUERY_CHARS;
            case HEADER_NAME, HEADER_VALUE -> RFC7230_HEADER_CHARS;
            case BODY -> HTTP_BODY_CHARS;
            case COOKIE_NAME, COOKIE_VALUE -> RFC3986_UNRESERVED;
        };
    }
}