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
 * <p>QI-6: Converted from fixedValues() to dynamic algorithmic generation.</p>
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

    // QI-6: Dynamic generation components - fully converted from fixedValues()
    private final TypedGenerator<Integer> basePatternTypeGen = Generators.integers(1, 7);
    private final TypedGenerator<Integer> depthGen = Generators.integers(2, 6);
    private final TypedGenerator<Integer> scriptTagSelector = Generators.integers(1, 4);
    private final TypedGenerator<Integer> protocolSelector = Generators.integers(1, 4);
    private final TypedGenerator<Integer> encodingTypeGen = Generators.integers(1, 7);

    @Override
    public String next() {
        String basePattern = generateBasePattern();
        int encodingType = encodingTypeGen.next();

        return switch (encodingType) {
            case 1 -> mixUrlWithHtmlEntities(basePattern);
            case 2 -> mixUrlWithUnicodeEscapes(basePattern);
            case 3 -> mixUrlWithJavaScriptEscapes(basePattern);
            case 4 -> mixHtmlWithUnicodeEscapes(basePattern);
            case 5 -> mixBase64WithUrl(basePattern);
            case 6 -> mixUtf8OverlongWithUrl(basePattern);
            case 7 -> mixDifferentUrlFormats(basePattern);
            default -> basePattern;
        };
    }

    private String generateBasePattern() {
        return switch (basePatternTypeGen.next()) {
            case 1 -> generateTraversalPattern();
            case 2 -> generateScriptPattern();
            case 3 -> generateProtocolPattern();
            case 4 -> generateNullBytePattern();
            case 5 -> generateBackslashPattern();
            case 6 -> generateFileSchemePattern();
            case 7 -> generateMixedTraversalPattern();
            default -> "../";
        };
    }

    private String generateTraversalPattern() {
        int depth = depthGen.next();
        StringBuilder pattern = new StringBuilder();
        for (int i = 0; i < depth; i++) {
            pattern.append("../");
        }
        return pattern.toString();
    }

    private String generateScriptPattern() {
        String tag = generateScriptTag();
        return "<" + tag + ">";
    }

    private String generateProtocolPattern() {
        String protocol = generateProtocol();
        return protocol + ":";
    }

    private String generateNullBytePattern() {
        return Generators.booleans().next() ? "test\\x00path" : "path\0file";
    }

    private String generateBackslashPattern() {
        int depth = depthGen.next();
        StringBuilder pattern = new StringBuilder();
        for (int i = 0; i < depth; i++) {
            pattern.append("..\\");
        }
        return pattern.toString();
    }

    private String generateFileSchemePattern() {
        return "file://";
    }

    private String generateMixedTraversalPattern() {
        int depth = depthGen.next();
        StringBuilder pattern = new StringBuilder();
        for (int i = 0; i < depth; i++) {
            if (Generators.booleans().next()) {
                pattern.append("../");
            } else {
                pattern.append("..\\");
            }
        }
        return pattern.toString();
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

    // QI-6: Dynamic generation helper methods
    private String generateScriptTag() {
        return switch (scriptTagSelector.next()) {
            case 1 -> "script";
            case 2 -> "iframe";
            case 3 -> "object";
            case 4 -> "embed";
            default -> "script";
        };
    }

    private String generateProtocol() {
        return switch (protocolSelector.next()) {
            case 1 -> "javascript";
            case 2 -> "data";
            case 3 -> "vbscript";
            case 4 -> "file";
            default -> "javascript";
        };
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}