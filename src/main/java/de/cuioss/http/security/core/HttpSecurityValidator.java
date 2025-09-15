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
package de.cuioss.http.security.core;

import de.cuioss.http.security.exceptions.UrlSecurityException;
import org.jspecify.annotations.Nullable;

import java.util.function.Predicate;

/**
 * Core functional interface for HTTP security validation.
 *
 * <p>This interface defines the contract for validating HTTP components against security threats.
 * It follows the "String in, String out, throws on violation" pattern consistently across all
 * implementations, enabling clean functional programming patterns and easy composition.</p>
 *
 * <h3>Design Principles</h3>
 * <ul>
 *   <li><strong>Functional Interface</strong> - Can be used with lambda expressions and method references</li>
 *   <li><strong>Fail Secure</strong> - Throws UrlSecurityException on any security violation</li>
 *   <li><strong>String/throws Pattern</strong> - Simple contract: input string, output string, throws on failure</li>
 *   <li><strong>Composable</strong> - Multiple validators can be chained or combined</li>
 *   <li><strong>Thread Safe</strong> - Implementations should be thread-safe for concurrent use</li>
 * </ul>
 *
 * <h3>Usage Examples</h3>
 * <pre>
 * // Simple validation
 * HttpSecurityValidator pathValidator = input -> {
 *     if (input.contains("../")) {
 *         throw UrlSecurityException.builder()
 *             .failureType(UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED)
 *             .validationType(ValidationType.URL_PATH)
 *             .originalInput(input)
 *             .build();
 *     }
 *     return input;
 * };
 *
 * // Using with streams
 * List&lt;String&gt; validPaths = paths.stream()
 *     .map(pathValidator::validate)
 *     .collect(Collectors.toList());
 *
 * // Composing validators
 * HttpSecurityValidator compositeValidator = input ->
 *     secondValidator.validate(firstValidator.validate(input));
 * </pre>
 *
 * <h3>Implementation Guidelines</h3>
 * <ul>
 *   <li>Always validate the most dangerous patterns first</li>
 *   <li>Provide clear, actionable error messages in exceptions</li>
 *   <li>Consider performance - validators may be called frequently</li>
 *   <li>Be consistent with null handling (typically reject null inputs)</li>
 *   <li>Log security violations appropriately without exposing sensitive data</li>
 * </ul>
 *
 * Implements: Task B3 from HTTP verification specification
 *
 * @since 2.5
 * @see UrlSecurityException
 * @see ValidationType
 */
@FunctionalInterface
public interface HttpSecurityValidator {

    /**
     * Validates the input string and returns the sanitized/normalized version.
     *
     * <p>This method should examine the input for security violations and either:
     * <ul>
     *   <li>Return the input unchanged if it's safe</li>
     *   <li>Return a sanitized/normalized version if safe transformations are possible</li>
     *   <li>Throw UrlSecurityException if the input represents a security threat</li>
     * </ul>
     *
     * <p>The decision between sanitization and rejection depends on the specific validator
     * and security requirements. Critical security validators should prefer rejection
     * over sanitization to avoid bypasses.</p>
     *
     * @param value The input to validate. May be null depending on implementation requirements.
     * @return The validated, potentially sanitized or normalized value. Should not be null
     *         unless the input was null and null inputs are explicitly supported.
     * @throws UrlSecurityException If the input represents a security violation that cannot
     *         be safely sanitized. The exception should include detailed context about the
     *         failure for logging and debugging purposes.
     * @throws IllegalArgumentException If the input is malformed in a way that prevents
     *         security analysis (distinct from security violations).
     */
    String validate(@Nullable String value) throws UrlSecurityException;

    /**
     * Creates a composite validator that applies this validator followed by the given validator.
     *
     * <p>This is a convenience method for chaining validators. The resulting validator will:
     * <ol>
     *   <li>Apply this validator to the input</li>
     *   <li>Apply the {@code after} validator to the result</li>
     *   <li>Return the final result</li>
     * </ol>
     *
     * <p>If either validator throws an exception, the composition stops and the exception
     * is propagated.</p>
     *
     * @param after The validator to apply after this validator. Must not be null.
     * @return A composite validator that applies both validators in sequence.
     * @throws NullPointerException if {@code after} is null
     * @since 2.5
     */
    default HttpSecurityValidator andThen(HttpSecurityValidator after) {
        if (after == null) {
            throw new NullPointerException("after validator must not be null");
        }
        return value -> after.validate(this.validate(value));
    }

    /**
     * Creates a composite validator that applies the given validator followed by this validator.
     *
     * <p>This is a convenience method for chaining validators. The resulting validator will:
     * <ol>
     *   <li>Apply the {@code before} validator to the input</li>
     *   <li>Apply this validator to the result</li>
     *   <li>Return the final result</li>
     * </ol>
     *
     * @param before The validator to apply before this validator. Must not be null.
     * @return A composite validator that applies both validators in sequence.
     * @throws NullPointerException if {@code before} is null
     * @since 2.5
     */
    default HttpSecurityValidator compose(HttpSecurityValidator before) {
        if (before == null) {
            throw new NullPointerException("before validator must not be null");
        }
        return value -> this.validate(before.validate(value));
    }

    /**
     * Creates a validator that applies this validator only if the given predicate is true.
     * If the predicate is false, the input is returned unchanged.
     *
     * <p>This is useful for conditional validation based on input characteristics:</p>
     * <pre>
     * // Only validate non-empty strings
     * HttpSecurityValidator conditionalValidator = validator.when(s -> s != null && !s.isEmpty());
     *
     * // Only validate strings that look like URLs
     * HttpSecurityValidator urlValidator = validator.when(s -> s.startsWith("http"));
     * </pre>
     *
     * @param predicate The condition under which to apply this validator. Must not be null.
     * @return A conditional validator that only applies this validator when the predicate is true.
     * @throws NullPointerException if {@code predicate} is null
     * @since 2.5
     */
    default HttpSecurityValidator when(Predicate<String> predicate) {
        if (predicate == null) {
            throw new NullPointerException("predicate must not be null");
        }
        return value -> predicate.test(value) ? this.validate(value) : value;
    }

    /**
     * Creates an identity validator that always returns the input unchanged.
     * This is useful as a no-op validator or as a starting point for composition.
     *
     * @return An identity validator that performs no validation
     * @since 2.5
     */
    static HttpSecurityValidator identity() {
        return value -> value;
    }

    /**
     * Creates a validator that always rejects input with the specified failure type.
     * This is useful for creating validators that unconditionally block certain inputs.
     *
     * @param failureType The failure type to use in the exception
     * @param validationType The validation type context
     * @return A validator that always throws UrlSecurityException
     * @throws NullPointerException if either parameter is null
     * @since 2.5
     */
    static HttpSecurityValidator reject(UrlSecurityFailureType failureType, ValidationType validationType) {
        if (failureType == null) {
            throw new NullPointerException("failureType must not be null");
        }
        if (validationType == null) {
            throw new NullPointerException("validationType must not be null");
        }
        return value -> {
            throw UrlSecurityException.builder()
                    .failureType(failureType)
                    .validationType(validationType)
                    .originalInput(value != null ? value : "null")
                    .detail("Input unconditionally rejected")
                    .build();
        };
    }
}