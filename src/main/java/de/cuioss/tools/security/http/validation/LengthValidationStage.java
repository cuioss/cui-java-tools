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

import java.util.function.Predicate;

/**
 * Length validation stage with configurable limits for HTTP components.
 * 
 * <p>This stage enforces length limits on various HTTP components to prevent
 * denial-of-service attacks, buffer overflow attempts, and resource exhaustion.
 * The stage validates input length against component-specific limits:</p>
 * 
 * <ol>
 *   <li><strong>Path Length Validation</strong> - Enforces maximum URL path length</li>
 *   <li><strong>Parameter Length Validation</strong> - Validates parameter names and values</li>
 *   <li><strong>Header Length Validation</strong> - Checks header names and values</li>
 *   <li><strong>Cookie Length Validation</strong> - Validates cookie names and values</li>
 *   <li><strong>Body Size Validation</strong> - Enforces request/response body size limits</li>
 * </ol>
 * 
 * <h3>Design Principles</h3>
 * <ul>
 *   <li><strong>DoS Protection</strong> - Prevents resource exhaustion through size limits</li>
 *   <li><strong>Context-Sensitive</strong> - Different limits for different HTTP components</li>
 *   <li><strong>Performance Optimized</strong> - Simple length checks with O(1) complexity</li>
 *   <li><strong>RFC Compliant</strong> - Follows HTTP specification recommendations</li>
 * </ul>
 * 
 * <h3>Security Validations</h3>
 * <ul>
 *   <li><strong>Path Length</strong> - Prevents extremely long URL paths</li>
 *   <li><strong>Parameter Length</strong> - Limits parameter name and value sizes</li>
 *   <li><strong>Header Length</strong> - Enforces HTTP header size restrictions</li>
 *   <li><strong>Cookie Length</strong> - Validates cookie name and value sizes</li>
 *   <li><strong>Body Size</strong> - Prevents large payload attacks</li>
 * </ul>
 * 
 * <h3>Usage Examples</h3>
 * <pre>
 * // Create length validation stage
 * SecurityConfiguration config = SecurityConfiguration.defaults();
 * LengthValidationStage lengthValidator = new LengthValidationStage(config, ValidationType.URL_PATH);
 * 
 * // Validate path length
 * try {
 *     lengthValidator.validate("/api/users/123"); // Passes if within limit
 * } catch (UrlSecurityException e) {
 *     logger.warn("Path too long: {}", e.getFailureType());
 * }
 * 
 * // Validate parameter value
 * LengthValidationStage paramValidator = new LengthValidationStage(config, ValidationType.PARAMETER_VALUE);
 * try {
 *     paramValidator.validate("very_long_parameter_value"); // May fail if too long
 * } catch (UrlSecurityException e) {
 *     logger.warn("Parameter value too long: {}", e.getDetail());
 * }
 * 
 * // Validate with custom limits
 * SecurityConfiguration strictConfig = SecurityConfiguration.builder()
 *     .maxPathLength(1024)
 *     .maxParameterValueLength(256)
 *     .build();
 * LengthValidationStage strictValidator = new LengthValidationStage(strictConfig, ValidationType.URL_PATH);
 * </pre>
 * 
 * <h3>Performance Characteristics</h3>
 * <ul>
 *   <li>O(1) time complexity - simple length comparison</li>
 *   <li>Minimal memory overhead - no string manipulation</li>
 *   <li>Early termination on limit exceeded</li>
 *   <li>No regex or pattern matching overhead</li>
 * </ul>
 * 
 * <h3>Configuration Dependencies</h3>
 * <ul>
 *   <li><strong>maxPathLength</strong> - Maximum allowed path length</li>
 *   <li><strong>maxParameterNameLength/maxParameterValueLength</strong> - Parameter size limits</li>
 *   <li><strong>maxHeaderNameLength/maxHeaderValueLength</strong> - Header size limits</li>
 *   <li><strong>maxCookieNameLength/maxCookieValueLength</strong> - Cookie size limits</li>
 *   <li><strong>maxBodySize</strong> - Maximum body size in bytes</li>
 * </ul>
 * 
 * Implements: Task V4 from HTTP verification specification
 * 
 * @since 2.5
 * @see HttpSecurityValidator
 * @see SecurityConfiguration
 * @see ValidationType
 */
@Value
public class LengthValidationStage implements HttpSecurityValidator {

    /**
     * Security configuration controlling validation behavior.
     */
    SecurityConfiguration config;

    /**
     * Type of validation being performed (URL_PATH, PARAMETER_NAME, etc.).
     */
    ValidationType validationType;

    /**
     * Validates input length against component-specific limits.
     * 
     * <p>Processing logic:</p>
     * <ol>
     *   <li>Input validation - handles null/empty inputs</li>
     *   <li>Length calculation - gets input length in characters or bytes</li>
     *   <li>Limit lookup - determines appropriate limit based on validation type</li>
     *   <li>Comparison - checks if input exceeds configured limit</li>
     * </ol>
     * 
     * @param value The input string to validate for length limits
     * @return The original input if validation passes
     * @throws UrlSecurityException if length limits are exceeded:
     *         <ul>
     *           <li>PATH_TOO_LONG - if URL path exceeds maximum length</li>
     *           <li>INPUT_TOO_LONG - if other components exceed their limits</li>
     *         </ul>
     */
    @Override
    public String validate(String value) throws UrlSecurityException {
        if (value == null) {
            return null;
        }

        // Get input length in characters
        int inputLength = value.length();

        // Determine the appropriate limit and failure type based on validation type
        int limit = getMaxLength();
        UrlSecurityFailureType failureType = getFailureType();
        String componentName = getComponentName();

        // Check if input exceeds the limit
        if (inputLength > limit) {
            throw UrlSecurityException.builder()
                    .failureType(failureType)
                    .validationType(validationType)
                    .originalInput(value)
                    .detail(componentName + " length " + inputLength + " exceeds maximum " + limit)
                    .build();
        }

        // Validation passed - return original value
        return value;
    }

    /**
     * Gets the maximum allowed length for the current validation type.
     * 
     * @return Maximum length in characters (or bytes for body content)
     */
    private int getMaxLength() {
        return switch (validationType) {
            case URL_PATH -> config.maxPathLength();
            case PARAMETER_NAME -> config.maxParameterNameLength();
            case PARAMETER_VALUE -> config.maxParameterValueLength();
            case HEADER_NAME -> config.maxHeaderNameLength();
            case HEADER_VALUE -> config.maxHeaderValueLength();
            case COOKIE_NAME -> config.maxCookieNameLength();
            case COOKIE_VALUE -> config.maxCookieValueLength();
            case BODY -> (int) Math.min(config.maxBodySize(), Integer.MAX_VALUE);
        };
    }

    /**
     * Gets the appropriate failure type for the current validation type.
     * 
     * @return UrlSecurityFailureType corresponding to the validation context
     */
    private UrlSecurityFailureType getFailureType() {
        return switch (validationType) {
            case URL_PATH -> UrlSecurityFailureType.PATH_TOO_LONG;
            case PARAMETER_NAME, PARAMETER_VALUE, HEADER_NAME, HEADER_VALUE,
                COOKIE_NAME, COOKIE_VALUE, BODY -> UrlSecurityFailureType.INPUT_TOO_LONG;
        };
    }

    /**
     * Gets a human-readable component name for error messages.
     * 
     * @return Component name string for use in error details
     */
    private String getComponentName() {
        return switch (validationType) {
            case URL_PATH -> "URL path";
            case PARAMETER_NAME -> "Parameter name";
            case PARAMETER_VALUE -> "Parameter value";
            case HEADER_NAME -> "Header name";
            case HEADER_VALUE -> "Header value";
            case COOKIE_NAME -> "Cookie name";
            case COOKIE_VALUE -> "Cookie value";
            case BODY -> "Request body";
        };
    }

    /**
     * Creates a conditional validator that only processes inputs matching the condition.
     * 
     * @param condition The condition to test before validation
     * @return A conditional HttpSecurityValidator that applies length validation conditionally
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
     * Returns a string representation of this length validation stage.
     * 
     * @return String representation including validation type and configured limit
     */
    @Override
    public String toString() {
        return "LengthValidationStage{validationType=%s, maxLength=%d}".formatted(
                validationType, getMaxLength());
    }
}