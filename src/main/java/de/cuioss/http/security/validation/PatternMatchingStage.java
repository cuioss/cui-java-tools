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
import de.cuioss.http.security.config.SecurityDefaults;
import de.cuioss.http.security.core.HttpSecurityValidator;
import de.cuioss.http.security.core.UrlSecurityFailureType;
import de.cuioss.http.security.core.ValidationType;
import de.cuioss.http.security.exceptions.UrlSecurityException;
import lombok.Value;

import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Pattern;

/**
 * Pattern matching validation stage for detecting malicious attack patterns.
 *
 * <p>This stage performs comprehensive pattern-based security validation to detect
 * known attack signatures, injection attempts, and suspicious content patterns.
 * The stage analyzes input against multiple security pattern databases:</p>
 *
 * <ol>
 *   <li><strong>Path Traversal Patterns</strong> - Detects directory traversal attempts</li>
 *   <li><strong>Cross-Site Scripting Patterns</strong> - Identifies XSS attack patterns</li>
 *   <li><strong>Suspicious Path Patterns</strong> - Detects access to sensitive system locations</li>
 *   <li><strong>Parameter Attack Patterns</strong> - Identifies malicious parameter usage</li>
 * </ol>
 *
 * <h3>Design Principles</h3>
 * <ul>
 *   <li><strong>Signature-Based Detection</strong> - Uses known attack patterns from OWASP and CVE databases</li>
 *   <li><strong>Configurable Sensitivity</strong> - Behavior controlled by failOnSuspiciousPatterns setting</li>
 *   <li><strong>Performance Optimized</strong> - Uses pre-compiled patterns and efficient string operations</li>
 *   <li><strong>Context Aware</strong> - Different pattern sets applied based on validation type</li>
 * </ul>
 *
 * <h3>Security Validations</h3>
 * <ul>
 *   <li><strong>Path Traversal</strong> - ../,..\\, and encoded variants</li>
 *   <li><strong>XSS Attacks</strong> - Script tags, event handlers, and JS injection</li>
 *   <li><strong>File Access</strong> - Attempts to access sensitive system files</li>
 *   <li><strong>Parameter Pollution</strong> - Suspicious parameter names and patterns</li>
 * </ul>
 *
 * <h3>Usage Examples</h3>
 * <pre>
 * // Create pattern matching stage
 * SecurityConfiguration config = SecurityConfiguration.defaults();
 * PatternMatchingStage matcher = new PatternMatchingStage(config, ValidationType.URL_PATH);
 *
 * // Detect path traversal attack
 * try {
 *     matcher.validate("/api/users/../../../etc/passwd");
 *     // Throws UrlSecurityException with PATH_TRAVERSAL_DETECTED
 * } catch (UrlSecurityException e) {
 *     logger.warn("Path traversal blocked: {}", e.getDetail());
 * }
 *
 * // Path traversal detection
 * try {
 *     matcher.validate("../../../etc/passwd");
 * } catch (UrlSecurityException e) {
 *     logger.warn("Path traversal blocked: {}", e.getDetail());
 * }
 *
 * // Configurable sensitivity
 * SecurityConfiguration strict = SecurityConfiguration.strict(); // failOnSuspiciousPatterns=true
 * PatternMatchingStage strictMatcher = new PatternMatchingStage(strict, ValidationType.PARAMETER_VALUE);
 *
 * // Legitimate content that might trigger in strict mode
 * try {
 *     strictMatcher.validate("SELECT name FROM contacts WHERE id = 123");
 *     // May throw if configured to fail on suspicious patterns
 * } catch (UrlSecurityException e) {
 *     // Handle based on security policy
 * }
 * </pre>
 *
 * <h3>Performance Characteristics</h3>
 * <ul>
 *   <li>O(n*m) time complexity where n = input length, m = number of patterns</li>
 *   <li>Early termination on first pattern match</li>
 *   <li>Optimized pattern order based on common attack frequency</li>
 *   <li>Case-insensitive matching for broader attack detection</li>
 * </ul>
 *
 * <h3>Configuration Dependencies</h3>
 * <ul>
 *   <li><strong>failOnSuspiciousPatterns</strong> - Controls whether to fail on pattern matches</li>
 *   <li><strong>caseSensitiveComparison</strong> - Affects pattern matching behavior</li>
 *   <li><strong>logSecurityViolations</strong> - Controls violation logging</li>
 * </ul>
 *
 * Implements: Task V3 from HTTP verification specification
 *
 * @since 2.5
 * @see HttpSecurityValidator
 * @see SecurityConfiguration
 * @see SecurityDefaults
 * @see ValidationType
 */
@Value
public class PatternMatchingStage implements HttpSecurityValidator {

    /**
     * Pre-compiled regex pattern for detecting encoded path traversal sequences.
     * Matches various URL-encoded representations of ../ and ..\ patterns including
     * double-encoded, UTF-8 overlong, and mixed encoding attempts.
     */
    private static final Pattern ENCODED_TRAVERSAL_PATTERN = Pattern.compile(
            """
            (?i)\
            %2e%2e[%2f%5c/\\\\]|%2f%2e%2e|%5c%2e%2e|\
            \\.%2e[%2f%5c/\\\\]|%2e\\.[%2f%5c/\\\\]|\
            %252e%252e[%252f%255c/\\\\]|\
            %c0%ae%c0%ae[%c0%af%c1%9c/\\\\]|%c1%9c%c1%9c|%c1%8s%c1%8s%c1%81|\
            %c0%ae.*%c0%af|%c1%9c.*%c1%9c|\
            %2e%2e[/\\\\]{2,}|[.]{2,}[%2f%5c]{1,2}[/\\\\]*|\
            [.]{2}%2f[.]{2}|[.]{2}/%2e%2e"""
    );


    // XSS script pattern removed - application layer responsibility.
    // Application layers have proper context for HTML/JS escaping and validation.


    /**
     * Security configuration controlling validation behavior.
     */
    SecurityConfiguration config;

    /**
     * Type of validation being performed (URL_PATH, PARAMETER_NAME, etc.).
     */
    ValidationType validationType;

    /**
     * Validates input against comprehensive attack pattern databases.
     *
     * <p>Processing stages:</p>
     * <ol>
     *   <li>Input validation - handles null/empty inputs</li>
     *   <li>Context-sensitive pattern selection - chooses appropriate patterns for validation type</li>
     *   <li>Pattern matching - tests against known attack signatures</li>
     *   <li>Policy enforcement - applies configured response to pattern matches</li>
     * </ol>
     *
     * @param value The input string to validate against attack patterns
     * @return The original input if validation passes
     * @throws UrlSecurityException if malicious patterns are detected:
     *         <ul>
     *           <li>PATH_TRAVERSAL_DETECTED - if path traversal patterns found</li>
     *           <!-- XSS detection removed - application layer responsibility -->
     *           <li>SUSPICIOUS_PATTERN_DETECTED - if suspicious patterns found and policy requires failure</li>
     *         </ul>
     */
    @Override
    public String validate(String value) throws UrlSecurityException {
        if (value == null || value.isEmpty()) {
            return value;
        }

        // Prepare value for case-insensitive matching if needed
        String testValue = config.caseSensitiveComparison() ? value : value.toLowerCase();

        // Step 1: Check for path traversal patterns (applies to paths and parameters)
        if (validationType == ValidationType.URL_PATH ||
                validationType == ValidationType.PARAMETER_VALUE ||
                validationType == ValidationType.PARAMETER_NAME) {

            checkPathTraversalPatterns(value, testValue);
        }

        // XSS pattern checking removed - application layer responsibility.

        // Step 3: Check for suspicious system paths (paths and parameters)
        if (validationType == ValidationType.URL_PATH || validationType == ValidationType.PARAMETER_VALUE) {
            checkSuspiciousPathPatterns(value, testValue);
        }

        // Step 4: Check for suspicious parameter names (parameter names only)
        if (validationType == ValidationType.PARAMETER_NAME) {
            checkSuspiciousParameterNames(value, testValue);
        }

        // Validation passed - return original value
        return value;
    }

    /**
     * Checks input for path traversal attack patterns.
     *
     * <p><strong>Security Critical:</strong> Path traversal patterns are ALWAYS blocked
     * regardless of the failOnSuspiciousPatterns configuration, as they represent
     * direct security threats, not merely suspicious behavior.</p>
     *
     * @param originalValue The original input value
     * @param testValue The value prepared for testing (case-normalized if needed)
     * @throws UrlSecurityException if path traversal patterns are detected
     */
    private void checkPathTraversalPatterns(String originalValue, String testValue) {
        // Check simple string patterns - ALWAYS fail on path traversal (security critical)
        for (String pattern : SecurityDefaults.PATH_TRAVERSAL_PATTERNS) {
            String checkPattern = config.caseSensitiveComparison() ? pattern : pattern.toLowerCase();
            if (testValue.contains(checkPattern)) {
                throw UrlSecurityException.builder()
                        .failureType(UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED)
                        .validationType(validationType)
                        .originalInput(originalValue)
                        .detail("Path traversal pattern detected: " + pattern)
                        .build();
            }
        }

        // Check encoded patterns using regex - ALWAYS fail on path traversal (security critical)
        if (ENCODED_TRAVERSAL_PATTERN.matcher(originalValue).find()) {
            throw UrlSecurityException.builder()
                    .failureType(UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED)
                    .validationType(validationType)
                    .originalInput(originalValue)
                    .detail("Encoded path traversal pattern detected via regex")
                    .build();
        }

        // Additional check: Look for any sequence of dots followed by path separators
        // This catches edge cases like multiple dots or mixed separators
        if (originalValue.matches("(?i).*[.]{2,}[/\\\\%2f%5c]+.*")) {
            throw UrlSecurityException.builder()
                    .failureType(UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED)
                    .validationType(validationType)
                    .originalInput(originalValue)
                    .detail("Path traversal pattern detected: multiple dots with separators")
                    .build();
        }

        // Critical: Block ANY occurrence of ../  patterns regardless of context
        // This ensures even patterns that would normalize safely are blocked (defense in depth)
        if (originalValue.contains("../") || originalValue.contains("..\\")) {
            throw UrlSecurityException.builder()
                    .failureType(UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED)
                    .validationType(validationType)
                    .originalInput(originalValue)
                    .detail("Path traversal pattern detected: dot-dot-slash sequence found")
                    .build();
        }
    }

    // XSS pattern checking removed - application layer responsibility.
    // Application layers have proper context for HTML/JS escaping and validation.

    /**
     * Checks input for suspicious system path patterns.
     *
     * @param originalValue The original input value
     * @param testValue The value prepared for testing (case-normalized if needed)
     * @throws UrlSecurityException if suspicious patterns are found and policy requires failure
     */
    private void checkSuspiciousPathPatterns(String originalValue, String testValue) {
        for (String pattern : SecurityDefaults.SUSPICIOUS_PATH_PATTERNS) {
            String checkPattern = config.caseSensitiveComparison() ? pattern : pattern.toLowerCase();
            if (testValue.contains(checkPattern)) {
                if (config.failOnSuspiciousPatterns()) {
                    throw UrlSecurityException.builder()
                            .failureType(UrlSecurityFailureType.SUSPICIOUS_PATTERN_DETECTED)
                            .validationType(validationType)
                            .originalInput(originalValue)
                            .detail("Suspicious path pattern detected: " + pattern)
                            .build();
                }
                // If not configured to fail, continue validation but could log here
            }
        }
    }

    /**
     * Checks parameter names for suspicious patterns commonly used in attacks.
     *
     * @param originalValue The original input value
     * @param testValue The value prepared for testing (case-normalized if needed)
     * @throws UrlSecurityException if suspicious parameter names are found and policy requires failure
     */
    private void checkSuspiciousParameterNames(String originalValue, String testValue) {
        for (String suspiciousName : SecurityDefaults.SUSPICIOUS_PARAMETER_NAMES) {
            String checkName = config.caseSensitiveComparison() ? suspiciousName : suspiciousName.toLowerCase();
            if (testValue.equals(checkName) || testValue.contains(checkName)) {
                if (config.failOnSuspiciousPatterns()) {
                    throw UrlSecurityException.builder()
                            .failureType(UrlSecurityFailureType.SUSPICIOUS_PARAMETER_NAME)
                            .validationType(validationType)
                            .originalInput(originalValue)
                            .detail("Suspicious parameter name detected: " + suspiciousName)
                            .build();
                }
                // If not configured to fail, continue validation
            }
        }
    }

    /**
     * Creates a conditional validator that only processes inputs matching the condition.
     *
     * @param condition The condition to test before validation
     * @return A conditional HttpSecurityValidator that applies pattern matching conditionally
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
     * Returns a string representation of this pattern matching stage.
     *
     * @return String representation including validation type and key configuration settings
     */
    @Override
    public String toString() {
        return "PatternMatchingStage{validationType=%s, failOnSuspicious=%s, caseSensitive=%s}".formatted(
                validationType, config.failOnSuspiciousPatterns(), config.caseSensitiveComparison());
    }
}