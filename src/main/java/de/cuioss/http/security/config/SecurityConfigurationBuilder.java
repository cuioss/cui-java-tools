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
package de.cuioss.http.security.config;

import org.jspecify.annotations.Nullable;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * Builder class for constructing {@link SecurityConfiguration} instances with fluent API.
 *
 * <p>This builder provides a convenient way to construct SecurityConfiguration objects
 * with sensible defaults while allowing fine-grained control over all security settings.
 * The builder follows the standard builder pattern with method chaining.</p>
 *
 * <h3>Design Principles</h3>
 * <ul>
 *   <li><strong>Fluent API</strong> - All setter methods return the builder for chaining</li>
 *   <li><strong>Sensible Defaults</strong> - Pre-configured with reasonable security defaults</li>
 *   <li><strong>Validation</strong> - Input validation on all parameters</li>
 *   <li><strong>Immutability</strong> - Produces immutable SecurityConfiguration instances</li>
 * </ul>
 *
 * <h3>Usage Examples</h3>
 * <pre>
 * // Basic configuration with defaults
 * SecurityConfiguration config = SecurityConfiguration.builder().build();
 *
 * // Custom configuration
 * SecurityConfiguration custom = SecurityConfiguration.builder()
 *     .maxPathLength(2048)
 *     .allowPathTraversal(false)
 *     .maxParameterCount(50)
 *     .requireSecureCookies(true)
 *     .addBlockedHeaderName("X-Debug")
 *     .addAllowedContentType("application/json")
 *     .addAllowedContentType("text/plain")
 *     .build();
 *
 * // Chain multiple settings
 * SecurityConfiguration strict = SecurityConfiguration.builder()
 *     .pathSecurity(1024, false)
 *     .cookieSecurity(true, true, 10, 64, 512)
 *     .bodySecurity(1024 * 1024, Set.of("application/json"))
 *     .encoding(false, false, false, true)
 *     .policies(true, true, true)
 *     .build();
 * </pre>
 *
 * <h3>Default Values</h3>
 * <p>The builder is initialized with balanced default values that provide reasonable
 * security without being overly restrictive:</p>
 * <ul>
 *   <li>Path length: 4096 characters</li>
 *   <li>Parameter count: 100</li>
 *   <li>Header count: 50</li>
 *   <li>Cookie count: 20</li>
 *   <li>Body size: 5MB</li>
 *   <li>Path traversal: disabled</li>
 *   <li>Cookie security flags: recommended but not required</li>
 * </ul>
 *
 * Implements: Task C2 from HTTP verification specification
 *
 * @since 2.5
 * @see SecurityConfiguration
 */
public class SecurityConfigurationBuilder {

    // Path Security defaults
    private int maxPathLength = 4096;
    private boolean allowPathTraversal = false;
    private boolean allowDoubleEncoding = false;

    // Parameter Security defaults
    private int maxParameterCount = 100;
    private int maxParameterNameLength = 128;
    private int maxParameterValueLength = 2048;

    // Header Security defaults
    private int maxHeaderCount = 50;
    private int maxHeaderNameLength = 128;
    private int maxHeaderValueLength = 2048;
    private @Nullable Set<String> allowedHeaderNames = null;
    private Set<String> blockedHeaderNames = new HashSet<>();

    // Cookie Security defaults
    private int maxCookieCount = 20;
    private int maxCookieNameLength = 128;
    private int maxCookieValueLength = 2048;
    private boolean requireSecureCookies = false;
    private boolean requireHttpOnlyCookies = false;

    // Body Security defaults
    private long maxBodySize = 5 * 1024 * 1024; // 5MB
    private @Nullable Set<String> allowedContentTypes = null;
    private Set<String> blockedContentTypes = new HashSet<>();

    // Encoding Security defaults
    private boolean allowNullBytes = false;
    private boolean allowControlCharacters = false;
    private boolean allowHighBitCharacters = true;
    private boolean normalizeUnicode = false;

    // General Policy defaults
    private boolean caseSensitiveComparison = false;
    private boolean failOnSuspiciousPatterns = false;
    private boolean logSecurityViolations = true;

    /**
     * Package-private constructor for internal use.
     */
    SecurityConfigurationBuilder() {
        // Initialize with default values already set above
    }

    // === Path Security Methods ===

    /**
     * Sets the maximum allowed path length.
     *
     * @param maxLength Maximum path length in characters (must be positive)
     * @return This builder for method chaining
     * @throws IllegalArgumentException if maxLength is not positive
     */
    public SecurityConfigurationBuilder maxPathLength(int maxLength) {
        if (maxLength <= 0) {
            throw new IllegalArgumentException("maxPathLength must be positive, got: " + maxLength);
        }
        this.maxPathLength = maxLength;
        return this;
    }

    /**
     * Sets whether path traversal patterns (../) are allowed.
     *
     * @param allow true to allow path traversal, false to block it
     * @return This builder for method chaining
     */
    public SecurityConfigurationBuilder allowPathTraversal(boolean allow) {
        this.allowPathTraversal = allow;
        return this;
    }

    /**
     * Sets whether double URL encoding is allowed.
     *
     * @param allow true to allow double encoding, false to block it
     * @return This builder for method chaining
     */
    public SecurityConfigurationBuilder allowDoubleEncoding(boolean allow) {
        this.allowDoubleEncoding = allow;
        return this;
    }

    /**
     * Configures path security settings in one call.
     *
     * @param maxLength Maximum path length
     * @param allowTraversal Whether to allow path traversal
     * @return This builder for method chaining
     */
    public SecurityConfigurationBuilder pathSecurity(int maxLength, boolean allowTraversal) {
        return maxPathLength(maxLength).allowPathTraversal(allowTraversal);
    }

    // === Parameter Security Methods ===

    /**
     * Sets the maximum number of query parameters allowed.
     *
     * @param maxCount Maximum parameter count (must be non-negative)
     * @return This builder for method chaining
     * @throws IllegalArgumentException if maxCount is negative
     */
    public SecurityConfigurationBuilder maxParameterCount(int maxCount) {
        if (maxCount < 0) {
            throw new IllegalArgumentException("maxParameterCount must be non-negative, got: " + maxCount);
        }
        this.maxParameterCount = maxCount;
        return this;
    }

    /**
     * Sets the maximum length for parameter names.
     *
     * @param maxLength Maximum name length (must be positive)
     * @return This builder for method chaining
     * @throws IllegalArgumentException if maxLength is not positive
     */
    public SecurityConfigurationBuilder maxParameterNameLength(int maxLength) {
        if (maxLength <= 0) {
            throw new IllegalArgumentException("maxParameterNameLength must be positive, got: " + maxLength);
        }
        this.maxParameterNameLength = maxLength;
        return this;
    }

    /**
     * Sets the maximum length for parameter values.
     *
     * @param maxLength Maximum value length (must be positive)
     * @return This builder for method chaining
     * @throws IllegalArgumentException if maxLength is not positive
     */
    public SecurityConfigurationBuilder maxParameterValueLength(int maxLength) {
        if (maxLength <= 0) {
            throw new IllegalArgumentException("maxParameterValueLength must be positive, got: " + maxLength);
        }
        this.maxParameterValueLength = maxLength;
        return this;
    }

    /**
     * Configures parameter security settings in one call.
     *
     * @param maxCount Maximum parameter count
     * @param maxNameLength Maximum parameter name length
     * @param maxValueLength Maximum parameter value length
     * @return This builder for method chaining
     */
    public SecurityConfigurationBuilder parameterSecurity(int maxCount, int maxNameLength, int maxValueLength) {
        return maxParameterCount(maxCount)
                .maxParameterNameLength(maxNameLength)
                .maxParameterValueLength(maxValueLength);
    }

    // === Header Security Methods ===

    /**
     * Sets the maximum number of HTTP headers allowed.
     *
     * @param maxCount Maximum header count (must be non-negative)
     * @return This builder for method chaining
     * @throws IllegalArgumentException if maxCount is negative
     */
    public SecurityConfigurationBuilder maxHeaderCount(int maxCount) {
        if (maxCount < 0) {
            throw new IllegalArgumentException("maxHeaderCount must be non-negative, got: " + maxCount);
        }
        this.maxHeaderCount = maxCount;
        return this;
    }

    /**
     * Sets the maximum length for header names.
     *
     * @param maxLength Maximum name length (must be positive)
     * @return This builder for method chaining
     * @throws IllegalArgumentException if maxLength is not positive
     */
    public SecurityConfigurationBuilder maxHeaderNameLength(int maxLength) {
        if (maxLength <= 0) {
            throw new IllegalArgumentException("maxHeaderNameLength must be positive, got: " + maxLength);
        }
        this.maxHeaderNameLength = maxLength;
        return this;
    }

    /**
     * Sets the maximum length for header values.
     *
     * @param maxLength Maximum value length (must be positive)
     * @return This builder for method chaining
     * @throws IllegalArgumentException if maxLength is not positive
     */
    public SecurityConfigurationBuilder maxHeaderValueLength(int maxLength) {
        if (maxLength <= 0) {
            throw new IllegalArgumentException("maxHeaderValueLength must be positive, got: " + maxLength);
        }
        this.maxHeaderValueLength = maxLength;
        return this;
    }

    /**
     * Adds a header name to the allowed list. If the allowed list is null,
     * this method initializes it with the given header name.
     *
     * @param headerName Header name to allow (must not be null)
     * @return This builder for method chaining
     * @throws NullPointerException if headerName is null
     */
    public SecurityConfigurationBuilder addAllowedHeaderName(String headerName) {
        Objects.requireNonNull(headerName, "headerName must not be null");
        if (allowedHeaderNames == null) {
            allowedHeaderNames = new HashSet<>();
        }
        allowedHeaderNames.add(headerName);
        return this;
    }

    /**
     * Sets the complete list of allowed header names.
     *
     * @param headerNames Set of allowed header names (null means all allowed)
     * @return This builder for method chaining
     */
    public SecurityConfigurationBuilder allowedHeaderNames(@Nullable Set<String> headerNames) {
        this.allowedHeaderNames = headerNames != null ? new HashSet<>(headerNames) : null;
        return this;
    }

    /**
     * Adds a header name to the blocked list.
     *
     * @param headerName Header name to block (must not be null)
     * @return This builder for method chaining
     * @throws NullPointerException if headerName is null
     */
    public SecurityConfigurationBuilder addBlockedHeaderName(String headerName) {
        Objects.requireNonNull(headerName, "headerName must not be null");
        blockedHeaderNames.add(headerName);
        return this;
    }

    /**
     * Sets the complete list of blocked header names.
     *
     * @param headerNames Set of blocked header names (must not be null)
     * @return This builder for method chaining
     * @throws NullPointerException if headerNames is null
     */
    public SecurityConfigurationBuilder blockedHeaderNames(Set<String> headerNames) {
        Objects.requireNonNull(headerNames, "headerNames must not be null");
        this.blockedHeaderNames = new HashSet<>(headerNames);
        return this;
    }

    /**
     * Configures header security settings in one call.
     *
     * @param maxCount Maximum header count
     * @param maxNameLength Maximum header name length
     * @param maxValueLength Maximum header value length
     * @return This builder for method chaining
     */
    public SecurityConfigurationBuilder headerSecurity(int maxCount, int maxNameLength, int maxValueLength) {
        return maxHeaderCount(maxCount)
                .maxHeaderNameLength(maxNameLength)
                .maxHeaderValueLength(maxValueLength);
    }

    // === Cookie Security Methods ===

    /**
     * Sets the maximum number of cookies allowed.
     *
     * @param maxCount Maximum cookie count (must be non-negative)
     * @return This builder for method chaining
     * @throws IllegalArgumentException if maxCount is negative
     */
    public SecurityConfigurationBuilder maxCookieCount(int maxCount) {
        if (maxCount < 0) {
            throw new IllegalArgumentException("maxCookieCount must be non-negative, got: " + maxCount);
        }
        this.maxCookieCount = maxCount;
        return this;
    }

    /**
     * Sets the maximum length for cookie names.
     *
     * @param maxLength Maximum name length (must be positive)
     * @return This builder for method chaining
     * @throws IllegalArgumentException if maxLength is not positive
     */
    public SecurityConfigurationBuilder maxCookieNameLength(int maxLength) {
        if (maxLength <= 0) {
            throw new IllegalArgumentException("maxCookieNameLength must be positive, got: " + maxLength);
        }
        this.maxCookieNameLength = maxLength;
        return this;
    }

    /**
     * Sets the maximum length for cookie values.
     *
     * @param maxLength Maximum value length (must be positive)
     * @return This builder for method chaining
     * @throws IllegalArgumentException if maxLength is not positive
     */
    public SecurityConfigurationBuilder maxCookieValueLength(int maxLength) {
        if (maxLength <= 0) {
            throw new IllegalArgumentException("maxCookieValueLength must be positive, got: " + maxLength);
        }
        this.maxCookieValueLength = maxLength;
        return this;
    }

    /**
     * Sets whether all cookies must have the Secure flag.
     *
     * @param require true to require Secure flag on all cookies
     * @return This builder for method chaining
     */
    public SecurityConfigurationBuilder requireSecureCookies(boolean require) {
        this.requireSecureCookies = require;
        return this;
    }

    /**
     * Sets whether all cookies must have the HttpOnly flag.
     *
     * @param require true to require HttpOnly flag on all cookies
     * @return This builder for method chaining
     */
    public SecurityConfigurationBuilder requireHttpOnlyCookies(boolean require) {
        this.requireHttpOnlyCookies = require;
        return this;
    }

    /**
     * Configures cookie security settings in one call.
     *
     * @param requireSecure Whether to require Secure flag
     * @param requireHttpOnly Whether to require HttpOnly flag
     * @param maxCount Maximum cookie count
     * @param maxNameLength Maximum cookie name length
     * @param maxValueLength Maximum cookie value length
     * @return This builder for method chaining
     */
    public SecurityConfigurationBuilder cookieSecurity(boolean requireSecure, boolean requireHttpOnly,
            int maxCount, int maxNameLength, int maxValueLength) {
        return requireSecureCookies(requireSecure)
                .requireHttpOnlyCookies(requireHttpOnly)
                .maxCookieCount(maxCount)
                .maxCookieNameLength(maxNameLength)
                .maxCookieValueLength(maxValueLength);
    }

    // === Body Security Methods ===

    /**
     * Sets the maximum body size in bytes.
     *
     * @param maxSize Maximum body size (must be non-negative)
     * @return This builder for method chaining
     * @throws IllegalArgumentException if maxSize is negative
     */
    public SecurityConfigurationBuilder maxBodySize(long maxSize) {
        if (maxSize < 0) {
            throw new IllegalArgumentException("maxBodySize must be non-negative, got: " + maxSize);
        }
        this.maxBodySize = maxSize;
        return this;
    }

    /**
     * Adds a content type to the allowed list. If the allowed list is null,
     * this method initializes it with the given content type.
     *
     * @param contentType Content type to allow (must not be null)
     * @return This builder for method chaining
     * @throws NullPointerException if contentType is null
     */
    public SecurityConfigurationBuilder addAllowedContentType(String contentType) {
        Objects.requireNonNull(contentType, "contentType must not be null");
        if (allowedContentTypes == null) {
            allowedContentTypes = new HashSet<>();
        }
        allowedContentTypes.add(contentType);
        return this;
    }

    /**
     * Sets the complete list of allowed content types.
     *
     * @param contentTypes Set of allowed content types (null means all allowed)
     * @return This builder for method chaining
     */
    public SecurityConfigurationBuilder allowedContentTypes(@Nullable Set<String> contentTypes) {
        this.allowedContentTypes = contentTypes != null ? new HashSet<>(contentTypes) : null;
        return this;
    }

    /**
     * Adds a content type to the blocked list.
     *
     * @param contentType Content type to block (must not be null)
     * @return This builder for method chaining
     * @throws NullPointerException if contentType is null
     */
    public SecurityConfigurationBuilder addBlockedContentType(String contentType) {
        Objects.requireNonNull(contentType, "contentType must not be null");
        blockedContentTypes.add(contentType);
        return this;
    }

    /**
     * Sets the complete list of blocked content types.
     *
     * @param contentTypes Set of blocked content types (must not be null)
     * @return This builder for method chaining
     * @throws NullPointerException if contentTypes is null
     */
    public SecurityConfigurationBuilder blockedContentTypes(Set<String> contentTypes) {
        Objects.requireNonNull(contentTypes, "contentTypes must not be null");
        this.blockedContentTypes = new HashSet<>(contentTypes);
        return this;
    }

    /**
     * Configures body security settings in one call.
     *
     * @param maxSize Maximum body size
     * @param allowedTypes Set of allowed content types (null = all allowed)
     * @return This builder for method chaining
     */
    public SecurityConfigurationBuilder bodySecurity(long maxSize, @Nullable Set<String> allowedTypes) {
        return maxBodySize(maxSize).allowedContentTypes(allowedTypes);
    }

    // === Encoding Security Methods ===

    /**
     * Sets whether null bytes are allowed in content.
     *
     * @param allow true to allow null bytes, false to block them
     * @return This builder for method chaining
     */
    public SecurityConfigurationBuilder allowNullBytes(boolean allow) {
        this.allowNullBytes = allow;
        return this;
    }

    /**
     * Sets whether control characters are allowed in content.
     *
     * @param allow true to allow control characters, false to block them
     * @return This builder for method chaining
     */
    public SecurityConfigurationBuilder allowControlCharacters(boolean allow) {
        this.allowControlCharacters = allow;
        return this;
    }

    /**
     * Sets whether high-bit characters are allowed in content.
     *
     * @param allow true to allow high-bit characters, false to block them
     * @return This builder for method chaining
     */
    public SecurityConfigurationBuilder allowHighBitCharacters(boolean allow) {
        this.allowHighBitCharacters = allow;
        return this;
    }

    /**
     * Sets whether Unicode normalization should be performed.
     *
     * @param normalize true to normalize Unicode, false to leave as-is
     * @return This builder for method chaining
     */
    public SecurityConfigurationBuilder normalizeUnicode(boolean normalize) {
        this.normalizeUnicode = normalize;
        return this;
    }

    /**
     * Configures encoding security settings in one call.
     *
     * @param allowNulls Whether to allow null bytes
     * @param allowControls Whether to allow control characters
     * @param allowHighBit Whether to allow high-bit characters
     * @param normalizeUni Whether to normalize Unicode
     * @return This builder for method chaining
     */
    public SecurityConfigurationBuilder encoding(boolean allowNulls, boolean allowControls,
            boolean allowHighBit, boolean normalizeUni) {
        return allowNullBytes(allowNulls)
                .allowControlCharacters(allowControls)
                .allowHighBitCharacters(allowHighBit)
                .normalizeUnicode(normalizeUni);
    }

    // === General Policy Methods ===

    /**
     * Sets whether string comparisons should be case-sensitive.
     *
     * @param caseSensitive true for case-sensitive comparisons
     * @return This builder for method chaining
     */
    public SecurityConfigurationBuilder caseSensitiveComparison(boolean caseSensitive) {
        this.caseSensitiveComparison = caseSensitive;
        return this;
    }

    /**
     * Sets whether to fail on detection of suspicious patterns.
     *
     * @param fail true to fail on suspicious patterns, false to log only
     * @return This builder for method chaining
     */
    public SecurityConfigurationBuilder failOnSuspiciousPatterns(boolean fail) {
        this.failOnSuspiciousPatterns = fail;
        return this;
    }

    /**
     * Sets whether to log security violations.
     *
     * @param log true to enable logging, false to disable
     * @return This builder for method chaining
     */
    public SecurityConfigurationBuilder logSecurityViolations(boolean log) {
        this.logSecurityViolations = log;
        return this;
    }

    /**
     * Configures general policy settings in one call.
     *
     * @param caseSensitive Whether comparisons are case-sensitive
     * @param failOnSuspicious Whether to fail on suspicious patterns
     * @param logViolations Whether to log security violations
     * @return This builder for method chaining
     */
    public SecurityConfigurationBuilder policies(boolean caseSensitive, boolean failOnSuspicious, boolean logViolations) {
        return caseSensitiveComparison(caseSensitive)
                .failOnSuspiciousPatterns(failOnSuspicious)
                .logSecurityViolations(logViolations);
    }

    /**
     * Builds the SecurityConfiguration with the current settings.
     *
     * @return A new immutable SecurityConfiguration instance
     * @throws IllegalArgumentException if any configuration values are invalid
     */
    public SecurityConfiguration build() {
        return new SecurityConfiguration(
                maxPathLength, allowPathTraversal, allowDoubleEncoding,
                maxParameterCount, maxParameterNameLength, maxParameterValueLength,
                maxHeaderCount, maxHeaderNameLength, maxHeaderValueLength, allowedHeaderNames, blockedHeaderNames,
                maxCookieCount, maxCookieNameLength, maxCookieValueLength, requireSecureCookies, requireHttpOnlyCookies,
                maxBodySize, allowedContentTypes, blockedContentTypes,
                allowNullBytes, allowControlCharacters, allowHighBitCharacters, normalizeUnicode,
                caseSensitiveComparison, failOnSuspiciousPatterns, logSecurityViolations
        );
    }
}