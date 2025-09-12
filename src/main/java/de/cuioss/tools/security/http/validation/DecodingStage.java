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
import java.util.function.Predicate;
import java.util.regex.Pattern;

/**
 * HTTP protocol-layer decoding validation stage with security checks.
 * 
 * <p>This stage performs URL decoding with security validation to detect and prevent
 * HTTP protocol-layer encoding attacks such as double encoding and overlong UTF-8 encoding.
 * <strong>Architectural Scope:</strong> Limited to HTTP/URL protocol encodings only.</p>
 * 
 * <ol>
 *   <li><strong>Double Encoding Detection</strong> - Identifies %25XX patterns indicating double encoding</li>
 *   <li><strong>Overlong UTF-8 Detection</strong> - Blocks malformed UTF-8 encoding attacks</li>
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
 *   <li><strong>Overlong UTF-8</strong> - Blocks malformed UTF-8 encoding attacks</li>
 *   <li><strong>Invalid Encoding</strong> - Catches malformed percent-encoded sequences</li>
 *   <li><strong>Unicode Normalization Attacks</strong> - Detects normalization changes that could alter meaning</li>
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
     * Security configuration controlling validation behavior.
     */
    SecurityConfiguration config;

    /**
     * Type of validation being performed (URL_PATH, PARAMETER_NAME, etc.).
     */
    ValidationType validationType;

    /**
     * Validates input through HTTP protocol-layer decoding with security checks.
     * 
     * <p><strong>Architectural Boundary:</strong> This stage operates strictly at the HTTP protocol layer,
     * handling URL-specific encoding schemes. Application-layer encodings (HTML entities, JS escapes) 
     * are handled by higher application layers where they have proper context.</p>
     * 
     * <p>HTTP Protocol Processing stages:</p>
     * <ol>
     *   <li>Double encoding detection - fails fast if %25XX patterns found</li>
     *   <li>UTF-8 overlong encoding detection - blocks malformed UTF-8 attack patterns</li>
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

        // Step 2: URL decode (HTTP protocol-layer appropriate)
        String decoded;
        try {
            decoded = URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw UrlSecurityException.builder()
                    .failureType(UrlSecurityFailureType.INVALID_ENCODING)
                    .validationType(validationType)
                    .originalInput(value)
                    .detail("URL decoding failed: " + e.getMessage())
                    .cause(e)
                    .build();
        }

        // Step 3: Unicode normalization with change detection
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