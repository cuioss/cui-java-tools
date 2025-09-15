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

import java.util.Set;
import java.util.stream.Collectors;

/**
 * Immutable record representing comprehensive security configuration for HTTP validation.
 *
 * <p>This record encapsulates all security policies and settings needed to configure
 * HTTP security validators. It provides a type-safe, immutable configuration object
 * that can be shared across multiple validation operations.</p>
 *
 * <h3>Design Principles</h3>
 * <ul>
 *   <li><strong>Immutability</strong> - Configuration cannot be modified once created</li>
 *   <li><strong>Type Safety</strong> - Strongly typed configuration parameters</li>
 *   <li><strong>Completeness</strong> - Covers all aspects of HTTP security validation</li>
 *   <li><strong>Composability</strong> - Easy to combine with builder patterns</li>
 * </ul>
 *
 * <h3>Configuration Categories</h3>
 * <ul>
 *   <li><strong>Path Security</strong> - Path traversal prevention, allowed patterns</li>
 *   <li><strong>Parameter Security</strong> - Query parameter validation rules</li>
 *   <li><strong>Header Security</strong> - HTTP header validation policies</li>
 *   <li><strong>Cookie Security</strong> - Cookie validation and security requirements</li>
 *   <li><strong>Body Security</strong> - Request/response body validation settings</li>
 *   <li><strong>Encoding Security</strong> - URL encoding and character validation</li>
 *   <li><strong>Length Limits</strong> - Size restrictions for various HTTP components</li>
 *   <li><strong>General Policies</strong> - Cross-cutting security concerns</li>
 * </ul>
 *
 * <h3>Usage Examples</h3>
 * <pre>
 * // Create with builder
 * SecurityConfiguration config = SecurityConfiguration.builder()
 *     .maxPathLength(2048)
 *     .allowPathTraversal(false)
 *     .maxParameterCount(100)
 *     .requireSecureCookies(true)
 *     .build();
 *
 * // Use in validation
 * PathValidator validator = new PathValidator(config);
 * validator.validate("/api/users/123");
 *
 * // Create restrictive configuration
 * SecurityConfiguration strict = SecurityConfiguration.strict();
 *
 * // Create permissive configuration
 * SecurityConfiguration lenient = SecurityConfiguration.lenient();
 * </pre>
 *
 * Implements: Task C1 from HTTP verification specification
 *
 * @param maxPathLength Maximum allowed path length in characters
 * @param allowPathTraversal Whether to allow path traversal patterns (../)
 * @param allowDoubleEncoding Whether to allow double URL encoding
 * @param maxParameterCount Maximum number of query parameters
 * @param maxParameterNameLength Maximum length of parameter names
 * @param maxParameterValueLength Maximum length of parameter values
 * @param maxHeaderCount Maximum number of HTTP headers
 * @param maxHeaderNameLength Maximum length of header names
 * @param maxHeaderValueLength Maximum length of header values
 * @param allowedHeaderNames Set of explicitly allowed header names (null = all allowed)
 * @param blockedHeaderNames Set of explicitly blocked header names
 * @param maxCookieCount Maximum number of cookies
 * @param maxCookieNameLength Maximum length of cookie names
 * @param maxCookieValueLength Maximum length of cookie values
 * @param requireSecureCookies Whether all cookies must have Secure flag
 * @param requireHttpOnlyCookies Whether all cookies must have HttpOnly flag
 * @param maxBodySize Maximum body size in bytes
 * @param allowedContentTypes Set of allowed content types (null = all allowed)
 * @param blockedContentTypes Set of blocked content types
 * @param allowNullBytes Whether to allow null bytes in content
 * @param allowControlCharacters Whether to allow control characters
 * @param allowHighBitCharacters Whether to allow high-bit characters
 * @param normalizeUnicode Whether to normalize Unicode characters
 * @param caseSensitiveComparison Whether string comparisons should be case-sensitive
 * @param failOnSuspiciousPatterns Whether to fail on detection of suspicious patterns
 * @param logSecurityViolations Whether to log security violations
 *
 * @since 2.5
 * @see SecurityConfigurationBuilder
 */
public record SecurityConfiguration(
// Path Security
int maxPathLength,
boolean allowPathTraversal,
boolean allowDoubleEncoding,

// Parameter Security
int maxParameterCount,
int maxParameterNameLength,
int maxParameterValueLength,

// Header Security
int maxHeaderCount,
int maxHeaderNameLength,
int maxHeaderValueLength,
@Nullable Set<String> allowedHeaderNames,
Set<String> blockedHeaderNames,

// Cookie Security
int maxCookieCount,
int maxCookieNameLength,
int maxCookieValueLength,
boolean requireSecureCookies,
boolean requireHttpOnlyCookies,

// Body Security
long maxBodySize,
@Nullable Set<String> allowedContentTypes,
Set<String> blockedContentTypes,

// Encoding Security
boolean allowNullBytes,
boolean allowControlCharacters,
boolean allowHighBitCharacters,
boolean normalizeUnicode,

// General Policies
boolean caseSensitiveComparison,
boolean failOnSuspiciousPatterns,
boolean logSecurityViolations
) {

    /**
     * Creates a SecurityConfiguration with validation of constraints.
     */
    public SecurityConfiguration {
        // Validate length limits are positive
        if (maxPathLength <= 0) {
            throw new IllegalArgumentException("maxPathLength must be positive, got: " + maxPathLength);
        }
        if (maxParameterCount < 0) {
            throw new IllegalArgumentException("maxParameterCount must be non-negative, got: " + maxParameterCount);
        }
        if (maxParameterNameLength <= 0) {
            throw new IllegalArgumentException("maxParameterNameLength must be positive, got: " + maxParameterNameLength);
        }
        if (maxParameterValueLength <= 0) {
            throw new IllegalArgumentException("maxParameterValueLength must be positive, got: " + maxParameterValueLength);
        }
        if (maxHeaderCount < 0) {
            throw new IllegalArgumentException("maxHeaderCount must be non-negative, got: " + maxHeaderCount);
        }
        if (maxHeaderNameLength <= 0) {
            throw new IllegalArgumentException("maxHeaderNameLength must be positive, got: " + maxHeaderNameLength);
        }
        if (maxHeaderValueLength <= 0) {
            throw new IllegalArgumentException("maxHeaderValueLength must be positive, got: " + maxHeaderValueLength);
        }
        if (maxCookieCount < 0) {
            throw new IllegalArgumentException("maxCookieCount must be non-negative, got: " + maxCookieCount);
        }
        if (maxCookieNameLength <= 0) {
            throw new IllegalArgumentException("maxCookieNameLength must be positive, got: " + maxCookieNameLength);
        }
        if (maxCookieValueLength <= 0) {
            throw new IllegalArgumentException("maxCookieValueLength must be positive, got: " + maxCookieValueLength);
        }
        if (maxBodySize < 0) {
            throw new IllegalArgumentException("maxBodySize must be non-negative, got: " + maxBodySize);
        }

        // Ensure sets are immutable and non-null
        allowedHeaderNames = allowedHeaderNames != null ?
                Set.copyOf(allowedHeaderNames) : null;
        blockedHeaderNames = blockedHeaderNames != null ?
                Set.copyOf(blockedHeaderNames) : Set.of();
        allowedContentTypes = allowedContentTypes != null ?
                Set.copyOf(allowedContentTypes) : null;
        blockedContentTypes = blockedContentTypes != null ?
                Set.copyOf(blockedContentTypes) : Set.of();
    }

    /**
     * Creates a builder for constructing SecurityConfiguration instances.
     *
     * @return A new SecurityConfigurationBuilder with default values
     */
    public static SecurityConfigurationBuilder builder() {
        return new SecurityConfigurationBuilder();
    }

    /**
     * Creates a strict security configuration with tight restrictions.
     * This configuration prioritizes security over compatibility.
     *
     * @return A SecurityConfiguration with strict security policies
     */
    public static SecurityConfiguration strict() {
        return builder()
                .maxPathLength(1024)
                .allowPathTraversal(false)
                .allowDoubleEncoding(false)
                .maxParameterCount(20)
                .maxParameterNameLength(64)
                .maxParameterValueLength(1024)
                .maxHeaderCount(20)
                .maxHeaderNameLength(64)
                .maxHeaderValueLength(1024)
                .maxCookieCount(10)
                .maxCookieNameLength(64)
                .maxCookieValueLength(1024)
                .requireSecureCookies(true)
                .requireHttpOnlyCookies(true)
                .maxBodySize(1024 * 1024) // 1MB
                .allowNullBytes(false)
                .allowControlCharacters(false)
                .allowHighBitCharacters(false)
                .normalizeUnicode(true)
                .caseSensitiveComparison(true)
                .failOnSuspiciousPatterns(true)
                .logSecurityViolations(true)
                .build();
    }

    /**
     * Creates a lenient security configuration with relaxed restrictions.
     * This configuration prioritizes compatibility over strict security.
     *
     * @return A SecurityConfiguration with lenient security policies
     */
    public static SecurityConfiguration lenient() {
        return builder()
                .maxPathLength(8192)
                .allowPathTraversal(false) // Still don't allow this
                .allowDoubleEncoding(true)
                .maxParameterCount(500)
                .maxParameterNameLength(256)
                .maxParameterValueLength(8192)
                .maxHeaderCount(100)
                .maxHeaderNameLength(256)
                .maxHeaderValueLength(8192)
                .maxCookieCount(50)
                .maxCookieNameLength(256)
                .maxCookieValueLength(8192)
                .requireSecureCookies(false)
                .requireHttpOnlyCookies(false)
                .maxBodySize(10 * 1024 * 1024) // 10MB
                .allowNullBytes(false) // Still don't allow this
                .allowControlCharacters(true)
                .allowHighBitCharacters(true)
                .normalizeUnicode(false)
                .caseSensitiveComparison(false)
                .failOnSuspiciousPatterns(false)
                .logSecurityViolations(true)
                .build();
    }

    /**
     * Creates a default security configuration with balanced security and compatibility.
     *
     * @return A SecurityConfiguration with default security policies
     */
    public static SecurityConfiguration defaults() {
        return builder().build();
    }

    /**
     * Checks if the configuration allows a specific header name.
     *
     * @param headerName The header name to check
     * @return true if the header is allowed, false if blocked
     */
    public boolean isHeaderAllowed(String headerName) {
        if (headerName == null) {
            return false;
        }

        // Check blocked list first
        String checkName = caseSensitiveComparison ? headerName : headerName.toLowerCase();
        Set<String> blocked = caseSensitiveComparison ? blockedHeaderNames :
                blockedHeaderNames.stream().map(String::toLowerCase).collect(Collectors.toSet());

        if (blocked.contains(checkName)) {
            return false;
        }

        // If there's an allow list, check it
        if (allowedHeaderNames != null) {
            Set<String> allowed = caseSensitiveComparison ? allowedHeaderNames :
                    allowedHeaderNames.stream().map(String::toLowerCase).collect(Collectors.toSet());
            return allowed.contains(checkName);
        }

        // No allow list means all headers are allowed (except blocked ones)
        return true;
    }

    /**
     * Checks if the configuration allows a specific content type.
     *
     * @param contentType The content type to check
     * @return true if the content type is allowed, false if blocked
     */
    public boolean isContentTypeAllowed(String contentType) {
        if (contentType == null) {
            return false;
        }

        // Check blocked list first
        String checkType = caseSensitiveComparison ? contentType : contentType.toLowerCase();
        Set<String> blocked = caseSensitiveComparison ? blockedContentTypes :
                blockedContentTypes.stream().map(String::toLowerCase).collect(Collectors.toSet());

        if (blocked.contains(checkType)) {
            return false;
        }

        // If there's an allow list, check it
        if (allowedContentTypes != null) {
            Set<String> allowed = caseSensitiveComparison ? allowedContentTypes :
                    allowedContentTypes.stream().map(String::toLowerCase).collect(Collectors.toSet());
            return allowed.contains(checkType);
        }

        // No allow list means all content types are allowed (except blocked ones)
        return true;
    }

    /**
     * Checks if this configuration is considered "strict" based on key security settings.
     *
     * @return true if this configuration uses strict security policies
     */
    public boolean isStrict() {
        return !allowPathTraversal &&
                !allowDoubleEncoding &&
                !allowNullBytes &&
                !allowControlCharacters &&
                requireSecureCookies &&
                requireHttpOnlyCookies &&
                failOnSuspiciousPatterns &&
                maxPathLength <= 1024 &&
                maxBodySize <= 1024 * 1024;
    }

    /**
     * Checks if this configuration is considered "lenient" based on key security settings.
     *
     * @return true if this configuration uses lenient security policies
     */
    public boolean isLenient() {
        return allowDoubleEncoding ||
                allowControlCharacters ||
                maxBodySize > 5 * 1024 * 1024;
    }

    /**
     * Returns a copy of this configuration with modified path security settings.
     *
     * @param maxLength The new maximum path length
     * @param allowTraversal Whether to allow path traversal
     * @return A new SecurityConfiguration with updated path settings
     */
    public SecurityConfiguration withPathSecurity(int maxLength, boolean allowTraversal) {
        return new SecurityConfiguration(
                maxLength, allowTraversal, allowDoubleEncoding,
                maxParameterCount, maxParameterNameLength, maxParameterValueLength,
                maxHeaderCount, maxHeaderNameLength, maxHeaderValueLength, allowedHeaderNames, blockedHeaderNames,
                maxCookieCount, maxCookieNameLength, maxCookieValueLength, requireSecureCookies, requireHttpOnlyCookies,
                maxBodySize, allowedContentTypes, blockedContentTypes,
                allowNullBytes, allowControlCharacters, allowHighBitCharacters, normalizeUnicode,
                caseSensitiveComparison, failOnSuspiciousPatterns, logSecurityViolations
        );
    }

    /**
     * Returns a copy of this configuration with modified cookie security settings.
     *
     * @param requireSecure Whether to require Secure flag
     * @param requireHttpOnly Whether to require HttpOnly flag
     * @return A new SecurityConfiguration with updated cookie settings
     */
    public SecurityConfiguration withCookieSecurity(boolean requireSecure, boolean requireHttpOnly) {
        return new SecurityConfiguration(
                maxPathLength, allowPathTraversal, allowDoubleEncoding,
                maxParameterCount, maxParameterNameLength, maxParameterValueLength,
                maxHeaderCount, maxHeaderNameLength, maxHeaderValueLength, allowedHeaderNames, blockedHeaderNames,
                maxCookieCount, maxCookieNameLength, maxCookieValueLength, requireSecure, requireHttpOnly,
                maxBodySize, allowedContentTypes, blockedContentTypes,
                allowNullBytes, allowControlCharacters, allowHighBitCharacters, normalizeUnicode,
                caseSensitiveComparison, failOnSuspiciousPatterns, logSecurityViolations
        );
    }

    /**
     * Returns a copy of this configuration with logging enabled or disabled.
     *
     * @param enableLogging Whether to enable security violation logging
     * @return A new SecurityConfiguration with updated logging setting
     */
    public SecurityConfiguration withLogging(boolean enableLogging) {
        return new SecurityConfiguration(
                maxPathLength, allowPathTraversal, allowDoubleEncoding,
                maxParameterCount, maxParameterNameLength, maxParameterValueLength,
                maxHeaderCount, maxHeaderNameLength, maxHeaderValueLength, allowedHeaderNames, blockedHeaderNames,
                maxCookieCount, maxCookieNameLength, maxCookieValueLength, requireSecureCookies, requireHttpOnlyCookies,
                maxBodySize, allowedContentTypes, blockedContentTypes,
                allowNullBytes, allowControlCharacters, allowHighBitCharacters, normalizeUnicode,
                caseSensitiveComparison, failOnSuspiciousPatterns, enableLogging
        );
    }
}