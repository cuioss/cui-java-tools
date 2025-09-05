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
package de.cuioss.tools.security.http.exceptions;

import de.cuioss.tools.base.Preconditions;
import de.cuioss.tools.security.http.core.UrlSecurityFailureType;
import de.cuioss.tools.security.http.core.ValidationType;
import org.jspecify.annotations.Nullable;

import java.util.Objects;
import java.util.Optional;

/**
 * Main exception for HTTP security validation failures.
 * Extends RuntimeException to enable clean functional interface usage and fail-fast behavior.
 * 
 * <h3>Design Principles</h3>
 * <ul>
 *   <li><strong>Fail Secure</strong> - Throws on any security violation for immediate handling</li>
 *   <li><strong>Rich Context</strong> - Provides detailed failure information for debugging and logging</li>
 *   <li><strong>Builder Pattern</strong> - Fluent API for exception construction</li>
 *   <li><strong>Immutable</strong> - All fields are final and thread-safe</li>
 * </ul>
 * 
 * <h3>Usage Examples</h3>
 * <pre>
 * // Simple security violation
 * throw UrlSecurityException.builder()
 *     .failureType(UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED)
 *     .validationType(ValidationType.URL_PATH)
 *     .originalInput("../../../etc/passwd")
 *     .build();
 * 
 * // Detailed violation with sanitized input
 * throw UrlSecurityException.builder()
 *     .failureType(UrlSecurityFailureType.INVALID_CHARACTER)
 *     .validationType(ValidationType.PARAMETER_VALUE)
 *     .originalInput("user&lt;script&gt;alert(1)&lt;/script&gt;")
 *     .sanitizedInput("userscriptalert1script")
 *     .detail("Removed script tags and special characters")
 *     .build();
 * 
 * // Chained exception
 * throw UrlSecurityException.builder()
 *     .failureType(UrlSecurityFailureType.INVALID_ENCODING)
 *     .validationType(ValidationType.URL_PATH)
 *     .originalInput("%ZZ%invalid")
 *     .cause(originalException)
 *     .build();
 * </pre>
 * 
 * Implements: Task B2 from HTTP verification specification
 * 
 * @since 2.5
 */
public class UrlSecurityException extends RuntimeException {

    private final UrlSecurityFailureType failureType;
    private final ValidationType validationType;
    private final String originalInput;
    private final String sanitizedInput;
    private final String detail;

    /**
     * Creates a new UrlSecurityException with the specified parameters.
     * Use the {@link #builder()} method for easier construction.
     * 
     * @param failureType The type of security failure that occurred
     * @param validationType The type of HTTP component being validated
     * @param originalInput The original input that caused the security violation
     * @param sanitizedInput Optional sanitized version of the input (may be null)
     * @param detail Optional additional detail about the failure (may be null)
     * @param cause Optional underlying cause exception (may be null)
     */
    private UrlSecurityException(UrlSecurityFailureType failureType,
            ValidationType validationType,
            String originalInput,
            @Nullable String sanitizedInput,
            @Nullable String detail,
            @Nullable Throwable cause) {
        super(buildMessage(failureType, validationType, originalInput, detail), cause);
        this.failureType = Objects.requireNonNull(failureType, "failureType must not be null");
        this.validationType = Objects.requireNonNull(validationType, "validationType must not be null");
        this.originalInput = Objects.requireNonNull(originalInput, "originalInput must not be null");
        this.sanitizedInput = sanitizedInput;
        this.detail = detail;
    }

    /**
     * Creates a new builder for constructing UrlSecurityException instances.
     * 
     * @return A new Builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Gets the type of security failure that occurred.
     * 
     * @return The failure type, never null
     */
    public UrlSecurityFailureType getFailureType() {
        return failureType;
    }

    /**
     * Gets the type of HTTP component that was being validated.
     * 
     * @return The validation type, never null
     */
    public ValidationType getValidationType() {
        return validationType;
    }

    /**
     * Gets the original input that caused the security violation.
     * 
     * @return The original input, never null
     */
    public String getOriginalInput() {
        return originalInput;
    }

    /**
     * Gets the sanitized version of the input, if available.
     * 
     * @return The sanitized input wrapped in Optional, or empty if not provided
     */
    public Optional<String> getSanitizedInput() {
        return Optional.ofNullable(sanitizedInput);
    }

    /**
     * Gets additional detail about the security failure.
     * 
     * @return Additional detail wrapped in Optional, or empty if not provided
     */
    public Optional<String> getDetail() {
        return Optional.ofNullable(detail);
    }

    /**
     * Builds a comprehensive error message from the exception components.
     * 
     * @param failureType The type of failure
     * @param validationType The type of validation
     * @param originalInput The input that caused the failure
     * @param detail Optional additional detail
     * @return A formatted error message
     */
    private static String buildMessage(UrlSecurityFailureType failureType,
            ValidationType validationType,
            String originalInput,
            @Nullable String detail) {
        StringBuilder sb = new StringBuilder();
        sb.append("Security validation failed [").append(validationType).append("]: ");
        sb.append(failureType.getDescription());

        if (detail != null && !detail.trim().isEmpty()) {
            sb.append(" - ").append(detail);
        }

        // Safely truncate input for logging to prevent log injection
        String truncatedInput = truncateForLogging(originalInput);
        sb.append(" (input: '").append(truncatedInput).append("')");

        return sb.toString();
    }

    /**
     * Safely truncates input for logging to prevent log injection attacks.
     * 
     * @param input The input to truncate
     * @return Safe truncated input
     */
    private static String truncateForLogging(String input) {
        if (input == null) {
            return "null";
        }

        // Remove control characters and limit length
        String safe = input.replaceAll("[\\r\\n\\t\\x00-\\x1F\\x7F]", "?");

        if (safe.length() > 200) {
            return safe.substring(0, 200) + "...";
        }

        return safe;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }

        UrlSecurityException that = (UrlSecurityException) obj;
        return Objects.equals(failureType, that.failureType) &&
                Objects.equals(validationType, that.validationType) &&
                Objects.equals(originalInput, that.originalInput) &&
                Objects.equals(sanitizedInput, that.sanitizedInput) &&
                Objects.equals(detail, that.detail) &&
                Objects.equals(getCause(), that.getCause());
    }

    @Override
    public int hashCode() {
        return Objects.hash(failureType, validationType, originalInput,
                sanitizedInput, detail, getCause());
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "{" +
                "failureType=" + failureType +
                ", validationType=" + validationType +
                ", originalInput='" + truncateForLogging(originalInput) + '\'' +
                ", sanitizedInput='" + (sanitizedInput != null ? truncateForLogging(sanitizedInput) : null) + '\'' +
                ", detail='" + detail + '\'' +
                ", cause=" + getCause() +
                '}';
    }

    /**
     * Builder for constructing UrlSecurityException instances with a fluent API.
     * All required fields must be set before calling {@link #build()}.
     */
    public static class Builder {
        private UrlSecurityFailureType failureType;
        private ValidationType validationType;
        private String originalInput;
        private String sanitizedInput;
        private String detail;
        private Throwable cause;

        private Builder() {
            // Private constructor - use UrlSecurityException.builder()
        }

        /**
         * Sets the failure type.
         * 
         * @param failureType The type of security failure, must not be null
         * @return This builder instance for method chaining
         */
        public Builder failureType(UrlSecurityFailureType failureType) {
            this.failureType = failureType;
            return this;
        }

        /**
         * Sets the validation type.
         * 
         * @param validationType The type of HTTP component being validated, must not be null
         * @return This builder instance for method chaining
         */
        public Builder validationType(ValidationType validationType) {
            this.validationType = validationType;
            return this;
        }

        /**
         * Sets the original input that caused the security violation.
         * 
         * @param originalInput The original input, must not be null
         * @return This builder instance for method chaining
         */
        public Builder originalInput(String originalInput) {
            this.originalInput = originalInput;
            return this;
        }

        /**
         * Sets the sanitized input (optional).
         * 
         * @param sanitizedInput The sanitized version of the input, may be null
         * @return This builder instance for method chaining
         */
        public Builder sanitizedInput(@Nullable String sanitizedInput) {
            this.sanitizedInput = sanitizedInput;
            return this;
        }

        /**
         * Sets additional detail about the failure (optional).
         * 
         * @param detail Additional detail information, may be null
         * @return This builder instance for method chaining
         */
        public Builder detail(@Nullable String detail) {
            this.detail = detail;
            return this;
        }

        /**
         * Sets the underlying cause exception (optional).
         * 
         * @param cause The underlying cause, may be null
         * @return This builder instance for method chaining
         */
        public Builder cause(@Nullable Throwable cause) {
            this.cause = cause;
            return this;
        }

        /**
         * Builds and returns a new UrlSecurityException instance.
         * All required fields (failureType, validationType, originalInput) must be set.
         * 
         * @return A new UrlSecurityException instance
         * @throws IllegalArgumentException if any required field is not set
         */
        public UrlSecurityException build() {
            Preconditions.checkArgument(failureType != null, "failureType must be set");
            Preconditions.checkArgument(validationType != null, "validationType must be set");
            Preconditions.checkArgument(originalInput != null, "originalInput must be set");

            return new UrlSecurityException(failureType, validationType, originalInput,
                    sanitizedInput, detail, cause);
        }
    }
}