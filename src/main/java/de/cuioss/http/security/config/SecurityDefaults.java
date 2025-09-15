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

import java.util.Set;

/**
 * Comprehensive collection of default values and constants for HTTP security configuration.
 *
 * <p>This class provides centralized constants for all security-related configuration values,
 * making it easy to reference standard limits, common patterns, and recommended settings
 * across the HTTP security validation system.</p>
 *
 * <h3>Design Principles</h3>
 * <ul>
 *   <li><strong>Centralized Constants</strong> - Single source of truth for all defaults</li>
 *   <li><strong>Security-First</strong> - Defaults prioritize security while maintaining usability</li>
 *   <li><strong>Industry Standards</strong> - Based on RFC specifications and best practices</li>
 *   <li><strong>Categorized</strong> - Organized by HTTP component type for easy navigation</li>
 * </ul>
 *
 * <h3>Constant Categories</h3>
 * <ul>
 *   <li><strong>Length Limits</strong> - Maximum sizes for various HTTP components</li>
 *   <li><strong>Count Limits</strong> - Maximum quantities for collections</li>
 *   <li><strong>Security Patterns</strong> - Common attack patterns to detect</li>
 *   <li><strong>Content Types</strong> - Standard MIME types and their security implications</li>
 *   <li><strong>Character Sets</strong> - Character validation patterns</li>
 *   <li><strong>Configuration Presets</strong> - Pre-built configurations for common scenarios</li>
 * </ul>
 *
 * <h3>Usage Examples</h3>
 * <pre>
 * // Use constants in configuration
 * SecurityConfiguration config = SecurityConfiguration.builder()
 *     .maxPathLength(SecurityDefaults.MAX_PATH_LENGTH_DEFAULT)
 *     .maxParameterCount(SecurityDefaults.MAX_PARAMETER_COUNT_DEFAULT)
 *     .blockedContentTypes(SecurityDefaults.DANGEROUS_CONTENT_TYPES)
 *     .build();
 *
 * // Check against limits
 * if (path.length() > SecurityDefaults.MAX_PATH_LENGTH_STRICT) {
 *     throw new UrlSecurityException(...);
 * }
 *
 * // Use pattern constants
 * if (SecurityDefaults.PATH_TRAVERSAL_PATTERNS.stream().anyMatch(input::contains)) {
 *     // Handle path traversal attempt
 * }
 * </pre>
 *
 * Implements: Task C3 from HTTP verification specification
 *
 * @since 2.5
 * @see SecurityConfiguration
 * @see SecurityConfigurationBuilder
 */
public final class SecurityDefaults {

    /**
     * Private constructor to prevent instantiation.
     */
    private SecurityDefaults() {
        // Utility class - no instances
    }

    // ========== PATH SECURITY CONSTANTS ==========

    /** Maximum path length for strict security configurations */
    public static final int MAX_PATH_LENGTH_STRICT = 1024;

    /** Maximum path length for default security configurations */
    public static final int MAX_PATH_LENGTH_DEFAULT = 4096;

    /** Maximum path length for lenient security configurations */
    public static final int MAX_PATH_LENGTH_LENIENT = 8192;

    /** Common path traversal patterns to detect */
    public static final Set<String> PATH_TRAVERSAL_PATTERNS = Set.of(
            // Basic patterns
            "../", "..\\", "..\\/",

            // URL encoded patterns
            "..%2F", "..%5C", "%2E%2E/", "%2e%2e/", "%2E%2E%2F", "%2e%2e%2f",
            "%2e%2e%5c", "%2E%2E%5C", "%2f%2e%2e", "%5c%2e%2e",

            // Double encoded patterns
            "%252e%252e%252f", "%252e%252e%255c", "%252e%252e/", "%252e%252e\\",

            // Mixed patterns
            "....//", "....\\\\", ".%2E/", ".%2e/", "..//", "..\\\\",
            "%2e%2e//", "%2e%2e\\\\", "..%2f/", "..%5c\\", "..%2f", "..%5c", "/%2e%2e/",

            // UTF-8 overlong encodings (common bypass attempts)
            "..%c0%af", "..%c1%9c", "%c0%ae%c0%ae%c0%af", "%c1%8s%c1%8s%c1%81"
    );

    /** Patterns indicating potential directory traversal attempts and protocol handler attacks */
    public static final Set<String> SUSPICIOUS_PATH_PATTERNS = Set.of(
            "/etc/", "/proc/", "/sys/", "/dev/", "/boot/", "/root/",
            "\\windows\\", "\\system32\\", "\\users\\", "\\program files\\",
            "web.xml", "web.config", ".env", ".htaccess", ".htpasswd",
            "javascript:", "vbscript:", "data:", "file:"
    );

    // ========== PARAMETER SECURITY CONSTANTS ==========

    /** Maximum parameter count for strict security configurations */
    public static final int MAX_PARAMETER_COUNT_STRICT = 20;

    /** Maximum parameter count for default security configurations */
    public static final int MAX_PARAMETER_COUNT_DEFAULT = 100;

    /** Maximum parameter count for lenient security configurations */
    public static final int MAX_PARAMETER_COUNT_LENIENT = 500;

    /** Maximum parameter name length for strict configurations */
    public static final int MAX_PARAMETER_NAME_LENGTH_STRICT = 64;

    /** Maximum parameter name length for default configurations */
    public static final int MAX_PARAMETER_NAME_LENGTH_DEFAULT = 128;

    /** Maximum parameter name length for lenient configurations */
    public static final int MAX_PARAMETER_NAME_LENGTH_LENIENT = 256;

    /** Maximum parameter value length for strict configurations */
    public static final int MAX_PARAMETER_VALUE_LENGTH_STRICT = 1024;

    /** Maximum parameter value length for default configurations */
    public static final int MAX_PARAMETER_VALUE_LENGTH_DEFAULT = 2048;

    /** Maximum parameter value length for lenient configurations */
    public static final int MAX_PARAMETER_VALUE_LENGTH_LENIENT = 8192;

    /** Parameter names that are commonly used in HTTP-layer attacks */
    public static final Set<String> SUSPICIOUS_PARAMETER_NAMES = Set.of(
            "script", "include", "require", "file", "path", "url", "redirect", "forward"
    );

    // ========== HEADER SECURITY CONSTANTS ==========

    /** Maximum header count for strict security configurations */
    public static final int MAX_HEADER_COUNT_STRICT = 20;

    /** Maximum header count for default security configurations */
    public static final int MAX_HEADER_COUNT_DEFAULT = 50;

    /** Maximum header count for lenient security configurations */
    public static final int MAX_HEADER_COUNT_LENIENT = 100;

    /** Maximum header name length for strict configurations */
    public static final int MAX_HEADER_NAME_LENGTH_STRICT = 64;

    /** Maximum header name length for default configurations */
    public static final int MAX_HEADER_NAME_LENGTH_DEFAULT = 128;

    /** Maximum header name length for lenient configurations */
    public static final int MAX_HEADER_NAME_LENGTH_LENIENT = 256;

    /** Maximum header value length for strict configurations */
    public static final int MAX_HEADER_VALUE_LENGTH_STRICT = 1024;

    /** Maximum header value length for default configurations */
    public static final int MAX_HEADER_VALUE_LENGTH_DEFAULT = 2048;

    /** Maximum header value length for lenient configurations */
    public static final int MAX_HEADER_VALUE_LENGTH_LENIENT = 8192;

    /** Headers that should typically be blocked for security */
    public static final Set<String> DANGEROUS_HEADER_NAMES = Set.of(
            "X-Debug", "X-Test", "X-Development", "X-Admin",
            "X-Execute", "X-Command", "X-Shell", "X-Eval",
            "Proxy-Authorization", "Proxy-Connection"
    );

    /** Headers commonly used for debugging that may expose sensitive information */
    public static final Set<String> DEBUG_HEADER_NAMES = Set.of(
            "X-Debug", "X-Trace", "X-Profile", "X-Test-Mode",
            "X-Development", "X-Internal", "X-System-Info"
    );

    // ========== COOKIE SECURITY CONSTANTS ==========

    /** Maximum cookie count for strict security configurations */
    public static final int MAX_COOKIE_COUNT_STRICT = 10;

    /** Maximum cookie count for default security configurations */
    public static final int MAX_COOKIE_COUNT_DEFAULT = 20;

    /** Maximum cookie count for lenient security configurations */
    public static final int MAX_COOKIE_COUNT_LENIENT = 50;

    /** Maximum cookie name length for strict configurations */
    public static final int MAX_COOKIE_NAME_LENGTH_STRICT = 64;

    /** Maximum cookie name length for default configurations */
    public static final int MAX_COOKIE_NAME_LENGTH_DEFAULT = 128;

    /** Maximum cookie name length for lenient configurations */
    public static final int MAX_COOKIE_NAME_LENGTH_LENIENT = 256;

    /** Maximum cookie value length for strict configurations */
    public static final int MAX_COOKIE_VALUE_LENGTH_STRICT = 1024;

    /** Maximum cookie value length for default configurations */
    public static final int MAX_COOKIE_VALUE_LENGTH_DEFAULT = 2048;

    /** Maximum cookie value length for lenient configurations */
    public static final int MAX_COOKIE_VALUE_LENGTH_LENIENT = 8192;

    /** Cookie names that may indicate security issues */
    public static final Set<String> SUSPICIOUS_COOKIE_NAMES = Set.of(
            "debug", "test", "admin", "root", "system", "internal",
            "password", "secret", "token", "key", "auth", "session"
    );

    // ========== BODY SECURITY CONSTANTS ==========

    /** Maximum body size for strict security configurations (1MB) */
    public static final long MAX_BODY_SIZE_STRICT = 1024 * 1024;

    /** Maximum body size for default security configurations (5MB) */
    public static final long MAX_BODY_SIZE_DEFAULT = 5 * 1024 * 1024;

    /** Maximum body size for lenient security configurations (10MB) */
    public static final long MAX_BODY_SIZE_LENIENT = 10 * 1024 * 1024;

    /** Content types that are generally safe for most applications */
    public static final Set<String> SAFE_CONTENT_TYPES = Set.of(
            "application/json", "application/xml", "text/plain", "text/html",
            "application/x-www-form-urlencoded", "multipart/form-data",
            "text/css", "text/javascript", "application/javascript"
    );

    /** Content types that may pose security risks */
    public static final Set<String> DANGEROUS_CONTENT_TYPES = Set.of(
            "application/octet-stream", "application/x-executable",
            "application/x-msdownload", "application/x-msdos-program",
            "application/x-java-archive", "application/java-archive",
            "text/x-script", "text/x-shellscript", "application/x-sh"
    );

    /** Content types used for file uploads */
    public static final Set<String> UPLOAD_CONTENT_TYPES = Set.of(
            "multipart/form-data", "application/octet-stream",
            "image/jpeg", "image/png", "image/gif", "image/webp",
            "application/pdf", "text/csv", "application/zip"
    );

    // ========== CHARACTER SECURITY CONSTANTS ==========

    /** Null byte character */
    public static final char NULL_BYTE = '\0';

    /** Common control characters that may be problematic */
    public static final Set<Character> PROBLEMATIC_CONTROL_CHARS = Set.of(
            '\0', '\1', '\2', '\3', '\4', '\5', '\6', '\7',
            '\b', '\f', '\016', '\017', '\020', '\021', '\022',
            '\023', '\024', '\025', '\026', '\027', '\030', '\031'
    );

    /** Characters commonly used in injection attacks */
    public static final Set<Character> INJECTION_CHARACTERS = Set.of(
            '<', '>', '\'', '"', '&', ';', '|', '`', '$', '(', ')', '{', '}'
    );


    // XSS patterns removed - application layer responsibility.
    // Application layers have proper context for HTML escaping and validation.

    // ========== ENCODING CONSTANTS ==========

    /** Common double-encoding patterns */
    public static final Set<String> DOUBLE_ENCODING_PATTERNS = Set.of(
            "%25", "%2525", "%252e", "%252f", "%255c",
            "%2e%2e", "%2f%2e%2e", "%5c%2e%2e"
    );

    /** Unicode normalization forms that should be checked */
    public static final Set<String> UNICODE_NORMALIZATION_FORMS = Set.of(
            "NFC", "NFD", "NFKC", "NFKD"
    );

    // ========== SIZE LIMITS FOR DIFFERENT SECURITY LEVELS ==========

    /** Configuration preset for strict security requirements */
    public static final SecurityConfiguration STRICT_CONFIGURATION = SecurityConfiguration.builder()
            .maxPathLength(MAX_PATH_LENGTH_STRICT)
            .allowPathTraversal(false)
            .allowDoubleEncoding(false)
            .maxParameterCount(MAX_PARAMETER_COUNT_STRICT)
            .maxParameterNameLength(MAX_PARAMETER_NAME_LENGTH_STRICT)
            .maxParameterValueLength(MAX_PARAMETER_VALUE_LENGTH_STRICT)
            .maxHeaderCount(MAX_HEADER_COUNT_STRICT)
            .maxHeaderNameLength(MAX_HEADER_NAME_LENGTH_STRICT)
            .maxHeaderValueLength(MAX_HEADER_VALUE_LENGTH_STRICT)
            .blockedHeaderNames(DANGEROUS_HEADER_NAMES)
            .maxCookieCount(MAX_COOKIE_COUNT_STRICT)
            .maxCookieNameLength(MAX_COOKIE_NAME_LENGTH_STRICT)
            .maxCookieValueLength(MAX_COOKIE_VALUE_LENGTH_STRICT)
            .requireSecureCookies(true)
            .requireHttpOnlyCookies(true)
            .maxBodySize(MAX_BODY_SIZE_STRICT)
            .allowedContentTypes(SAFE_CONTENT_TYPES)
            .allowNullBytes(false)
            .allowControlCharacters(false)
            .allowHighBitCharacters(false)
            .normalizeUnicode(true)
            .caseSensitiveComparison(true)
            .failOnSuspiciousPatterns(true)
            .logSecurityViolations(true)
            .build();

    /** Configuration preset for balanced security and usability */
    public static final SecurityConfiguration DEFAULT_CONFIGURATION = SecurityConfiguration.builder()
            .maxPathLength(MAX_PATH_LENGTH_DEFAULT)
            .allowPathTraversal(false)
            .allowDoubleEncoding(false)
            .maxParameterCount(MAX_PARAMETER_COUNT_DEFAULT)
            .maxParameterNameLength(MAX_PARAMETER_NAME_LENGTH_DEFAULT)
            .maxParameterValueLength(MAX_PARAMETER_VALUE_LENGTH_DEFAULT)
            .maxHeaderCount(MAX_HEADER_COUNT_DEFAULT)
            .maxHeaderNameLength(MAX_HEADER_NAME_LENGTH_DEFAULT)
            .maxHeaderValueLength(MAX_HEADER_VALUE_LENGTH_DEFAULT)
            .blockedHeaderNames(DEBUG_HEADER_NAMES)
            .maxCookieCount(MAX_COOKIE_COUNT_DEFAULT)
            .maxCookieNameLength(MAX_COOKIE_NAME_LENGTH_DEFAULT)
            .maxCookieValueLength(MAX_COOKIE_VALUE_LENGTH_DEFAULT)
            .requireSecureCookies(false)
            .requireHttpOnlyCookies(false)
            .maxBodySize(MAX_BODY_SIZE_DEFAULT)
            .blockedContentTypes(DANGEROUS_CONTENT_TYPES)
            .allowNullBytes(false)
            .allowControlCharacters(false)
            .allowHighBitCharacters(true)
            .normalizeUnicode(false)
            .caseSensitiveComparison(false)
            .failOnSuspiciousPatterns(false)
            .logSecurityViolations(true)
            .build();

    /** Configuration preset for maximum compatibility */
    public static final SecurityConfiguration LENIENT_CONFIGURATION = SecurityConfiguration.builder()
            .maxPathLength(MAX_PATH_LENGTH_LENIENT)
            .allowPathTraversal(false) // Still don't allow this
            .allowDoubleEncoding(true)
            .maxParameterCount(MAX_PARAMETER_COUNT_LENIENT)
            .maxParameterNameLength(MAX_PARAMETER_NAME_LENGTH_LENIENT)
            .maxParameterValueLength(MAX_PARAMETER_VALUE_LENGTH_LENIENT)
            .maxHeaderCount(MAX_HEADER_COUNT_LENIENT)
            .maxHeaderNameLength(MAX_HEADER_NAME_LENGTH_LENIENT)
            .maxHeaderValueLength(MAX_HEADER_VALUE_LENGTH_LENIENT)
            // No blocked headers in lenient mode
            .maxCookieCount(MAX_COOKIE_COUNT_LENIENT)
            .maxCookieNameLength(MAX_COOKIE_NAME_LENGTH_LENIENT)
            .maxCookieValueLength(MAX_COOKIE_VALUE_LENGTH_LENIENT)
            .requireSecureCookies(false)
            .requireHttpOnlyCookies(false)
            .maxBodySize(MAX_BODY_SIZE_LENIENT)
            // Only block the most dangerous content types
            .blockedContentTypes(Set.of("application/x-executable", "application/x-msdos-program"))
            .allowNullBytes(false) // Still don't allow this
            .allowControlCharacters(true)
            .allowHighBitCharacters(true)
            .normalizeUnicode(false)
            .caseSensitiveComparison(false)
            .failOnSuspiciousPatterns(false)
            .logSecurityViolations(true)
            .build();
}