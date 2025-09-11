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
package de.cuioss.tools.security.http.validation;

import de.cuioss.tools.security.http.config.SecurityConfiguration;
import de.cuioss.tools.security.http.core.HttpSecurityValidator;
import de.cuioss.tools.security.http.core.UrlSecurityFailureType;
import de.cuioss.tools.security.http.core.ValidationType;
import de.cuioss.tools.security.http.exceptions.UrlSecurityException;
import lombok.Value;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.Map;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Multi-layer decoding validation stage with security checks.
 * 
 * <p>This stage performs URL decoding with security validation to detect and prevent
 * encoding-based attacks such as double encoding and Unicode normalization attacks.
 * The stage processes input through multiple layers:</p>
 * 
 * <ol>
 *   <li><strong>Double Encoding Detection</strong> - Identifies %25XX patterns indicating double encoding</li>
 *   <li><strong>URL Decoding</strong> - Performs standard URL percent-decoding</li>
 *   <li><strong>Unicode Normalization</strong> - Optionally normalizes Unicode and detects changes</li>
 * </ol>
 * 
 * <h3>Design Principles</h3>
 * <ul>
 *   <li><strong>Immutability</strong> - All fields are final, stage instances are immutable</li>
 *   <li><strong>Thread Safety</strong> - Safe for concurrent use across multiple threads</li>
 *   <li><strong>Performance</strong> - Uses pre-compiled patterns and efficient operations</li>
 *   <li><strong>Security First</strong> - Detects attacks before potentially dangerous decoding</li>
 * </ul>
 * 
 * <h3>Security Validations</h3>
 * <ul>
 *   <li><strong>Double Encoding</strong> - Detects %25XX patterns that could bypass filters</li>
 *   <li><strong>Invalid Encoding</strong> - Catches malformed percent-encoded sequences</li>
 *   <li><strong>Unicode Attacks</strong> - Detects normalization changes that could alter meaning</li>
 * </ul>
 * 
 * <h3>Usage Examples</h3>
 * <pre>
 * // Create decoding stage for URL paths
 * SecurityConfiguration config = SecurityConfiguration.defaults();
 * DecodingStage pathDecoder = new DecodingStage(config, ValidationType.URL_PATH);
 * 
 * // Validate and decode input
 * try {
 *     String decoded = pathDecoder.validate("/api/users%2F123");
 *     // Returns: "/api/users/123"
 * } catch (UrlSecurityException e) {
 *     // Handle security violation
 *     logger.warn("Encoding attack detected: {}", e.getFailureType());
 * }
 * 
 * // Double encoding detection
 * try {
 *     pathDecoder.validate("/admin%252F../users"); // %25 = encoded %
 *     // Throws UrlSecurityException with DOUBLE_ENCODING failure type
 * } catch (UrlSecurityException e) {
 *     // Attack blocked before decoding
 * }
 * </pre>
 * 
 * <h3>Performance Characteristics</h3>
 * <ul>
 *   <li>O(n) time complexity where n is input length</li>
 *   <li>Single pass through input for double encoding detection</li>
 *   <li>Minimal memory allocation - reuses pattern instances</li>
 *   <li>Early termination on security violations</li>
 * </ul>
 * 
 * Implements: Task V1 from HTTP verification specification
 * 
 * @since 2.5
 * @see HttpSecurityValidator
 * @see SecurityConfiguration
 * @see ValidationType
 */
@Value
public class DecodingStage implements HttpSecurityValidator {

    /**
     * Pre-compiled pattern for detecting double encoding patterns.
     * Matches %25 followed by two hexadecimal digits, indicating a percent sign
     * that was encoded as %25 and then encoded again.
     */
    private static final Pattern DOUBLE_ENCODING_PATTERN = Pattern.compile("%25[0-9a-fA-F]{2}");

    /**
     * Pre-compiled pattern for detecting UTF-8 overlong encoding attacks.
     * Matches UTF-8 overlong encodings commonly used to bypass security filters.
     * Includes common overlong encodings for ASCII characters and path separators.
     */
    private static final Pattern UTF8_OVERLONG_PATTERN = Pattern.compile(
            """
            (?i)\
            %c[0-1][0-9a-f][0-9a-f]|\
            %e0%[89][0-9a-f]%[89ab][0-9a-f]|\
            %f0%80%[89][0-9a-f]%[89ab][0-9a-f]|\
            %c0%[a-f][0-9a-f]|%c1%[0-9a-f][0-9a-f]|\
            %c0%ae|%c0%af|%c1%9c|%c1%81"""
    );

    /**
     * Pre-compiled pattern for detecting HTML entity patterns.
     * Matches both named entities (&lt;, &gt;, etc.) and numeric entities (&#47;, &#x2F;).
     */
    private static final Pattern HTML_ENTITY_PATTERN = Pattern.compile(
            "&(?:([a-zA-Z][a-zA-Z0-9]{1,8})|#(?:([0-9]{1,7})|x([0-9a-fA-F]{1,6})));?"
    );

    /**
     * Pre-compiled pattern for detecting JavaScript escape sequences.
     * Matches hex escapes (\x2f), Unicode escapes (\u002f), and octal escapes (\057).
     */
    private static final Pattern JS_ESCAPE_PATTERN = Pattern.compile(
            "\\\\(?:x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4})|([0-7]{1,3}))"
    );


    /**
     * Map of common HTML entities to their character equivalents.
     * Includes security-critical entities commonly used in attacks.
     */
    private static final Map<String, String> HTML_ENTITIES = createHtmlEntitiesMap();

    /**
     * Creates the HTML entities map. Separated to avoid Map.of() size limitations.
     */
    private static Map<String, String> createHtmlEntitiesMap() {
        return Map.of(
                "lt", "<",
                "gt", ">",
                "amp", "&",
                "quot", "\"",
                "apos", "'",
                "nbsp", "\u00A0",
                "sol", "/",
                "bsol", "\\",
                "colon", ":",
                "semi", ";"
        );
    }

    /**
     * Security configuration controlling validation behavior.
     */
    SecurityConfiguration config;

    /**
     * Type of validation being performed (URL_PATH, PARAMETER_NAME, etc.).
     */
    ValidationType validationType;

    /**
     * Validates input through multi-layer decoding with security checks.
     * 
     * <p>QI-2 Enhanced Processing stages:</p>
     * <ol>
     *   <li>Double encoding detection - fails fast if %25XX patterns found</li>
     *   <li>HTML entity decoding - decodes &lt;, &#47;, &#x2F;, etc.</li>
     *   <li>JavaScript escape decoding - decodes \x2f, \u002f, \057, etc.</li>
     *   <li>URL decoding - converts percent-encoded sequences to characters</li>
     *   <li>Unicode normalization - optionally normalizes and detects changes</li>
     * </ol>
     * 
     * @param value The input string to validate and decode
     * @return The validated and decoded string
     * @throws UrlSecurityException if any security violations are detected:
     *         <ul>
     *           <li>DOUBLE_ENCODING - if double encoding patterns are found</li>
     *           <li>INVALID_ENCODING - if URL decoding fails due to malformed input</li>
     *           <li>UNICODE_NORMALIZATION_CHANGED - if Unicode normalization changes the string</li>
     *         </ul>
     */
    @Override
    public String validate(String value) throws UrlSecurityException {
        if (value == null) {
            return null;
        }

        // Step 1: Detect double encoding before decoding
        if (!config.allowDoubleEncoding() && DOUBLE_ENCODING_PATTERN.matcher(value).find()) {
            throw UrlSecurityException.builder()
                    .failureType(UrlSecurityFailureType.DOUBLE_ENCODING)
                    .validationType(validationType)
                    .originalInput(value)
                    .detail("Double encoding pattern %25XX detected in input")
                    .build();
        }

        // Step 1.5: Detect UTF-8 overlong encoding attacks (always blocked - security critical)
        if (UTF8_OVERLONG_PATTERN.matcher(value).find()) {
            throw UrlSecurityException.builder()
                    .failureType(UrlSecurityFailureType.INVALID_ENCODING)
                    .validationType(validationType)
                    .originalInput(value)
                    .detail("UTF-8 overlong encoding attack detected")
                    .build();
        }

        // QI-2 Step 2: HTML entity decoding - decode HTML entities first
        String decoded = decodeHtmlEntities(value);

        // QI-2 Step 3: JavaScript escape decoding - decode JS escapes after HTML entities  
        decoded = decodeJavaScriptEscapes(decoded);

        // Step 4: URL decode (original step 2)
        try {
            decoded = URLDecoder.decode(decoded, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw UrlSecurityException.builder()
                    .failureType(UrlSecurityFailureType.INVALID_ENCODING)
                    .validationType(validationType)
                    .originalInput(value)
                    .detail("URL decoding failed: " + e.getMessage())
                    .cause(e)
                    .build();
        }

        // Step 5: Unicode normalization with change detection (original step 3)
        if (config.normalizeUnicode()) {
            String normalized = Normalizer.normalize(decoded, Normalizer.Form.NFC);
            if (!decoded.equals(normalized)) {
                // Normalization changed the string - potential attack
                throw UrlSecurityException.builder()
                        .failureType(UrlSecurityFailureType.UNICODE_NORMALIZATION_CHANGED)
                        .validationType(validationType)
                        .originalInput(value)
                        .sanitizedInput(normalized)
                        .detail("Unicode normalization changed string content")
                        .build();
            }
            decoded = normalized;
        }

        return decoded;
    }

    /**
     * Decodes HTML entities in the input string.
     * 
     * <p>Supports both named entities (&lt;, &gt;, &amp;, etc.) and numeric entities 
     * (&#47;, &#x2F;). Handles malformed entities gracefully by leaving them unchanged.</p>
     * 
     * @param input The input string that may contain HTML entities
     * @return The string with HTML entities decoded
     */
    private String decodeHtmlEntities(String input) {
        if (input == null || input.isEmpty()) {
            return input;
        }

        Matcher matcher = HTML_ENTITY_PATTERN.matcher(input);
        StringBuilder result = new StringBuilder();
        int lastEnd = 0;

        while (matcher.find()) {
            result.append(input, lastEnd, matcher.start());

            String namedEntity = matcher.group(1);
            String decimalEntity = matcher.group(2);
            String hexEntity = matcher.group(3);

            if (namedEntity != null) {
                // Named entity (e.g., &lt;)
                String replacement = HTML_ENTITIES.get(namedEntity.toLowerCase());
                if (replacement != null) {
                    result.append(replacement);
                } else {
                    // Unknown entity, keep as-is
                    result.append(matcher.group());
                }
            } else if (decimalEntity != null) {
                // Decimal numeric entity (e.g., &#47;)
                try {
                    int codePoint = Integer.parseInt(decimalEntity);
                    // Security: Only decode reasonable Unicode ranges to prevent abuse
                    if (Character.isValidCodePoint(codePoint) && codePoint <= 0x10FFFF && codePoint >= 1) {
                        result.append(Character.toChars(codePoint));
                    } else {
                        result.append(matcher.group());
                    }
                } catch (NumberFormatException e) {
                    result.append(matcher.group());
                }
            } else if (hexEntity != null) {
                // Hexadecimal numeric entity (e.g., &#x2F;)
                try {
                    int codePoint = Integer.parseInt(hexEntity, 16);
                    // Security: Only decode reasonable Unicode ranges to prevent abuse
                    if (Character.isValidCodePoint(codePoint) && codePoint <= 0x10FFFF && codePoint >= 1) {
                        result.append(Character.toChars(codePoint));
                    } else {
                        result.append(matcher.group());
                    }
                } catch (NumberFormatException e) {
                    result.append(matcher.group());
                }
            }

            lastEnd = matcher.end();
        }

        result.append(input, lastEnd, input.length());
        return result.toString();
    }

    /**
     * Decodes JavaScript escape sequences in the input string.
     * 
     * <p>Supports hex escapes (\x2f), Unicode escapes (\u002f), and octal escapes (\057).
     * Handles malformed escapes gracefully by leaving them unchanged.</p>
     * 
     * @param input The input string that may contain JavaScript escapes
     * @return The string with JavaScript escapes decoded
     */
    private String decodeJavaScriptEscapes(String input) {
        if (input == null || input.isEmpty()) {
            return input;
        }

        Matcher matcher = JS_ESCAPE_PATTERN.matcher(input);
        StringBuilder result = new StringBuilder();
        int lastEnd = 0;

        while (matcher.find()) {
            result.append(input, lastEnd, matcher.start());

            String hexEscape = matcher.group(1);
            String unicodeEscape = matcher.group(2);
            String octalEscape = matcher.group(3);

            if (hexEscape != null) {
                // Hex escape (e.g., \x2f)
                try {
                    int value = Integer.parseInt(hexEscape, 16);
                    result.append((char) value);
                } catch (NumberFormatException e) {
                    result.append(matcher.group());
                }
            } else if (unicodeEscape != null) {
                // Unicode escape (e.g., \u002f)
                try {
                    int value = Integer.parseInt(unicodeEscape, 16);
                    if (Character.isValidCodePoint(value)) {
                        result.append(Character.toChars(value));
                    } else {
                        result.append(matcher.group());
                    }
                } catch (NumberFormatException e) {
                    result.append(matcher.group());
                }
            } else if (octalEscape != null) {
                // Octal escape (e.g., \057)
                try {
                    int value = Integer.parseInt(octalEscape, 8);
                    if (value <= 255) { // Valid byte value
                        result.append((char) value);
                    } else {
                        result.append(matcher.group());
                    }
                } catch (NumberFormatException e) {
                    result.append(matcher.group());
                }
            }

            lastEnd = matcher.end();
        }

        result.append(input, lastEnd, input.length());
        return result.toString();
    }


    /**
     * Creates a conditional validator that only processes non-null, non-empty inputs.
     * 
     * @return A conditional HttpSecurityValidator that skips null/empty inputs
     */
    @Override
    public HttpSecurityValidator when(Predicate<String> condition) {
        return input -> {
            if (condition.test(input)) {
                return validate(input);
            }
            return input;
        };
    }

    /**
     * Returns a string representation of this decoding stage.
     * 
     * @return String representation including validation type and key config settings
     */
    @Override
    public String toString() {
        return "DecodingStage{validationType=%s, allowDoubleEncoding=%s, normalizeUnicode=%s}".formatted(
                validationType, config.allowDoubleEncoding(), config.normalizeUnicode());
    }
}