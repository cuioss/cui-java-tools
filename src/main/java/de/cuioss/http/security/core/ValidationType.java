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

/**
 * Enumeration of different types of HTTP components that require validation.
 * Each validation type may have different security requirements and validation rules.
 *
 * <h3>Design Principles</h3>
 * <ul>
 *   <li><strong>Type Safety</strong> - Provides compile-time safety for validation contexts</li>
 *   <li><strong>Context Awareness</strong> - Different validation rules per component type</li>
 *   <li><strong>Performance</strong> - Enables optimized validation strategies per type</li>
 *   <li><strong>Extensibility</strong> - Easy to add new HTTP component types</li>
 * </ul>
 *
 * <h3>Usage Example</h3>
 * <pre>
 * // Validate URL path component
 * validator.validate("/api/users", ValidationType.URL_PATH);
 *
 * // Validate query parameter name
 * validator.validate("userId", ValidationType.PARAMETER_NAME);
 *
 * // Validate HTTP header value
 * validator.validate("Bearer token123", ValidationType.HEADER_VALUE);
 * </pre>
 *
 * Supports: Task B2 from HTTP verification specification
 *
 * @since 2.5
 */
public enum ValidationType {

    /** URL path segments (e.g., "/api/users/123") */
    URL_PATH,

    /** Query parameter names (e.g., "userId" in "?userId=123") */
    PARAMETER_NAME,

    /** Query parameter values (e.g., "123" in "?userId=123") */
    PARAMETER_VALUE,

    /** HTTP header names (e.g., "Authorization", "Content-Type") */
    HEADER_NAME,

    /** HTTP header values (e.g., "Bearer token123", "application/json") */
    HEADER_VALUE,

    /** Cookie names (e.g., "JSESSIONID", "auth_token") */
    COOKIE_NAME,

    /** Cookie values (e.g., session identifiers, authentication tokens) */
    COOKIE_VALUE,

    /** Request/response body content */
    BODY;

    /**
     * Determines if this validation type requires URL decoding during processing.
     * URL decoding is typically needed for components that may contain percent-encoded sequences.
     *
     * @return true if URL decoding should be applied before validation
     */
    public boolean requiresDecoding() {
        return this == URL_PATH ||
                this == PARAMETER_NAME ||
                this == PARAMETER_VALUE;
    }

    /**
     * Determines if this validation type represents a key/name component.
     * Key components typically have more restrictive character sets and length limits.
     *
     * @return true if this type represents a key/name component
     */
    public boolean isKey() {
        return this == PARAMETER_NAME ||
                this == HEADER_NAME ||
                this == COOKIE_NAME;
    }

    /**
     * Determines if this validation type represents a value component.
     * Value components may allow a broader range of characters and content.
     *
     * @return true if this type represents a value component
     */
    public boolean isValue() {
        return this == PARAMETER_VALUE ||
                this == HEADER_VALUE ||
                this == COOKIE_VALUE;
    }

    /**
     * Determines if this validation type represents HTTP body content.
     * Body content has special handling for different content types and encodings.
     *
     * @return true if this type represents body content
     */
    public boolean isBody() {
        return this == BODY;
    }

    /**
     * Determines if this validation type represents a path component.
     * Path components have specific rules for traversal detection and normalization.
     *
     * @return true if this type represents a path component
     */
    public boolean isPath() {
        return this == URL_PATH;
    }

    /**
     * Determines if this validation type represents HTTP header content.
     * Header components (names and values) have RFC-specific formatting rules.
     *
     * @return true if this type represents header content
     */
    public boolean isHeader() {
        return this == HEADER_NAME || this == HEADER_VALUE;
    }

    /**
     * Determines if this validation type represents cookie content.
     * Cookie components have specific encoding and security requirements.
     *
     * @return true if this type represents cookie content
     */
    public boolean isCookie() {
        return this == COOKIE_NAME || this == COOKIE_VALUE;
    }

    /**
     * Determines if this validation type represents parameter content.
     * Parameter components are commonly targeted in injection attacks.
     *
     * @return true if this type represents parameter content
     */
    public boolean isParameter() {
        return this == PARAMETER_NAME || this == PARAMETER_VALUE;
    }
}