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
package de.cuioss.tools.security.http.generators.encoding;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;

import java.util.Base64;

/**
 * Generates mixed encoding attack patterns that combine different encoding schemes.
 * 
 * <p>
 * This generator creates attack patterns that mix different types of encoding
 * to bypass security controls that might only check for a single encoding type.
 * Unlike double encoding which applies the same encoding multiple times,
 * mixed encoding attacks combine different encoding schemes.
 * </p>
 * 
 * <h3>Attack Types Generated</h3>
 * <ul>
 *   <li>URL encoding mixed with HTML entity encoding</li>
 *   <li>URL encoding mixed with Unicode escapes (\\u sequences)</li>
 *   <li>URL encoding mixed with JavaScript escape sequences</li>
 *   <li>HTML entities mixed with Unicode escapes</li>
 *   <li>Base64 encoded payloads with URL encoding wrapper</li>
 *   <li>UTF-8 overlong encoding mixed with standard URL encoding</li>
 *   <li>Different URL encoding formats (% vs + for spaces)</li>
 * </ul>
 * 
 * <h3>Security Standards</h3>
 * <ul>
 *   <li>OWASP Top 10 - Injection Prevention</li>
 *   <li>CWE-20: Improper Input Validation</li>
 *   <li>CWE-116: Improper Encoding or Escaping of Output</li>
 *   <li>CWE-838: Inappropriate Encoding for Output Context</li>
 * </ul>
 * 
 * Implements: Generator for Task T6 from HTTP verification specification
 * 
 * @author Claude Code Generator
 * @since 2.5
 */
public class MixedEncodingAttackGenerator implements TypedGenerator<String> {

    private final TypedGenerator<String> basePatternGen = Generators.fixedValues(
            "../",
            "..\\",
            "../../",
            "../../../",
            "<script>",
            "javascript:",
            "data:",
            "vbscript:",
            "file://",
            "\\x00",
            "\0"
    );

    private final TypedGenerator<String> encodingTypeGen = Generators.fixedValues(
            "url_html",        // URL + HTML entities
            "url_unicode",     // URL + Unicode escapes
            "url_javascript",  // URL + JS escapes  
            "html_unicode",    // HTML entities + Unicode
            "base64_url",      // Base64 + URL
            "utf8_url",        // UTF-8 overlong + URL
            "mixed_url_formats" // Different URL encoding formats
    );

    @Override
    public String next() {
        String basePattern = basePatternGen.next();
        String encodingType = encodingTypeGen.next();

        return switch (encodingType) {
            case "url_html" -> mixUrlWithHtmlEntities(basePattern);
            case "url_unicode" -> mixUrlWithUnicodeEscapes(basePattern);
            case "url_javascript" -> mixUrlWithJavaScriptEscapes(basePattern);
            case "html_unicode" -> mixHtmlWithUnicodeEscapes(basePattern);
            case "base64_url" -> mixBase64WithUrl(basePattern);
            case "utf8_url" -> mixUtf8OverlongWithUrl(basePattern);
            case "mixed_url_formats" -> mixDifferentUrlFormats(basePattern);
            default -> basePattern;
        };
    }

    /**
     * Mix URL encoding with HTML entities.
     */
    private String mixUrlWithHtmlEntities(String pattern) {
        // First apply URL encoding to some characters
        String urlEncoded = pattern.replace(".", "%2e").replace("/", "%2f");

        // Then apply HTML entity encoding to others
        return urlEncoded.replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("&", "&amp;")
                .replace("'", "&#x27;");
    }

    /**
     * Mix URL encoding with Unicode escape sequences.
     */
    private String mixUrlWithUnicodeEscapes(String pattern) {
        // Apply URL encoding to some characters
        String urlEncoded = pattern.replace(".", "%2e");

        // Apply Unicode escapes to others
        return urlEncoded.replace("/", "\\\\u002f")
                .replace("\\", "\\\\u005c")
                .replace(":", "\\\\u003a");
    }

    /**
     * Mix URL encoding with JavaScript escape sequences.
     */
    private String mixUrlWithJavaScriptEscapes(String pattern) {
        // Apply URL encoding to some characters
        String urlEncoded = pattern.replace(".", "%2e");

        // Apply JavaScript escapes to others
        return urlEncoded.replace("/", "\\x2f")
                .replace("\\", "\\x5c")
                .replace(":", "\\x3a")
                .replace("\"", "\\x22");
    }

    /**
     * Mix HTML entities with Unicode escapes.
     */
    private String mixHtmlWithUnicodeEscapes(String pattern) {
        // Apply HTML entities to some characters
        String htmlEncoded = pattern.replace("<", "&lt;").replace(">", "&gt;");

        // Apply Unicode escapes to others
        return htmlEncoded.replace(".", "\\\\u002e")
                .replace("/", "\\\\u002f")
                .replace("\\", "\\\\u005c");
    }

    /**
     * Mix Base64 encoding with URL encoding.
     */
    private String mixBase64WithUrl(String pattern) {
        // Base64 encode the pattern
        String base64 = Base64.getEncoder().encodeToString(pattern.getBytes());

        // Then URL encode some special characters from the base64 result
        return base64.replace("+", "%2B")
                .replace("/", "%2F")
                .replace("=", "%3D");
    }

    /**
     * Mix UTF-8 overlong encoding with standard URL encoding.
     */
    private String mixUtf8OverlongWithUrl(String pattern) {
        StringBuilder result = new StringBuilder();

        for (char c : pattern.toCharArray()) {
            if (c == '.') {
                // UTF-8 overlong encoding for '.' (2-byte instead of 1-byte)
                result.append("%C0%AE");
            } else if (c == '/') {
                // Standard URL encoding
                result.append("%2F");
            } else if (c == '\\') {
                // UTF-8 overlong encoding for '\'
                result.append("%C0%5C");
            } else {
                result.append(c);
            }
        }

        return result.toString();
    }

    /**
     * Mix different URL encoding formats.
     */
    private String mixDifferentUrlFormats(String pattern) {
        // Mix percent encoding with plus encoding and different case
        return pattern.replace(" ", "+")         // Plus encoding for spaces
                .replace(".", "%2e")             // Lowercase percent encoding
                .replace("/", "%2F")             // Uppercase percent encoding
                .replace("\\", "%5c")            // Lowercase percent encoding
                .replace(":", "%3A");            // Uppercase percent encoding
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}