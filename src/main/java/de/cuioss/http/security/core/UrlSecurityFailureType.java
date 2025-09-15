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
 * Comprehensive enumeration of security failure types for URL validation.
 * Each failure type represents a specific class of security violation that
 * can occur during URL processing and validation.
 *
 * <h3>Design Principles</h3>
 * <ul>
 *   <li><strong>Comprehensive Coverage</strong> - Covers all major URL security attack vectors</li>
 *   <li><strong>Clear Categorization</strong> - Groups related failure types for easier handling</li>
 *   <li><strong>Descriptive Names</strong> - Self-documenting enum values</li>
 *   <li><strong>Immutable Design</strong> - Thread-safe for concurrent validation</li>
 * </ul>
 *
 * <h3>Usage Example</h3>
 * <pre>
 * if (containsPathTraversal(path)) {
 *     throw UrlSecurityException.builder()
 *         .failureType(UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED)
 *         .input(path)
 *         .build();
 * }
 * </pre>
 *
 * Implements: Task B1 from HTTP verification specification
 *
 * @since 2.5
 */
public enum UrlSecurityFailureType {

    // === Encoding Issues ===

    /** Invalid URL encoding sequences detected (e.g., incomplete percent encoding) */
    INVALID_ENCODING("Invalid URL encoding detected"),

    /** Double URL encoding patterns detected (e.g., %252e for double-encoded '.') */
    DOUBLE_ENCODING("Double URL encoding detected"),

    /** Unicode normalization changed the input, potentially bypassing security checks */
    UNICODE_NORMALIZATION_CHANGED("Unicode normalization altered input"),

    // === Path Traversal Attacks ===

    /** Path traversal patterns like "../" or equivalent encodings detected */
    PATH_TRAVERSAL_DETECTED("Path traversal pattern detected"),

    /** Attempt to escape from allowed directory structure detected */
    DIRECTORY_ESCAPE_ATTEMPT("Directory escape attempt detected"),

    // === Character-Based Attacks ===

    /** Invalid or dangerous characters found in URL */
    INVALID_CHARACTER("Invalid character detected"),

    /** Null byte injection attack detected (e.g., \u0000) */
    NULL_BYTE_INJECTION("Null byte injection detected"),

    /** Control characters that could manipulate processing detected */
    CONTROL_CHARACTERS("Control characters detected"),

    // === Size and Length Violations ===

    /** Path exceeds configured maximum length limits */
    PATH_TOO_LONG("Path exceeds maximum length"),

    /** Input exceeds configured maximum length limits */
    INPUT_TOO_LONG("Input exceeds maximum length"),

    /** Excessive directory nesting depth detected */
    EXCESSIVE_NESTING("Excessive directory nesting"),

    // === Pattern-Based Detection ===

    /** Suspicious patterns that match attack signatures */
    SUSPICIOUS_PATTERN_DETECTED("Suspicious pattern detected"),

    /** Suspicious parameter name commonly used in attacks */
    SUSPICIOUS_PARAMETER_NAME("Suspicious parameter name detected"),

    /** Known attack signatures from security databases */
    KNOWN_ATTACK_SIGNATURE("Known attack signature detected"),

    // XSS detection removed - application layer responsibility.
    // Application layers have proper context for HTML/JS escaping and validation.

    // === Structural Issues ===

    /** Input structure is malformed or corrupted */
    MALFORMED_INPUT("Malformed input structure"),

    /** Input structure violates expected format */
    INVALID_STRUCTURE("Invalid input structure"),

    // === Protocol Violations ===

    /** General protocol specification violation */
    PROTOCOL_VIOLATION("Protocol specification violation"),

    /** RFC specification violation (HTTP, URI, etc.) */
    RFC_VIOLATION("RFC specification violation"),

    // === IPv6 and Host-Based Attacks ===

    /** Invalid IPv6 address format detected */
    INVALID_IPV6_FORMAT("Invalid IPv6 address format"),

    /** Malformed URL structure detected */
    MALFORMED_URL("Malformed URL structure"),

    /** Invalid host format detected */
    INVALID_HOST_FORMAT("Invalid host format"),

    /** Invalid URL format detected */
    INVALID_URL_FORMAT("Invalid URL format");

    private final String description;

    /**
     * Creates a new failure type with the specified description.
     *
     * @param description Human-readable description of this failure type
     */
    UrlSecurityFailureType(String description) {
        this.description = description;
    }

    /**
     * Returns the human-readable description of this failure type.
     *
     * @return Description text suitable for logging and error reporting
     */
    public String getDescription() {
        return description;
    }

    /**
     * Indicates whether this failure type represents an encoding-related issue.
     *
     * @return true if this is an encoding-related failure type
     */
    public boolean isEncodingIssue() {
        return this == INVALID_ENCODING ||
                this == DOUBLE_ENCODING ||
                this == UNICODE_NORMALIZATION_CHANGED;
    }

    /**
     * Indicates whether this failure type represents a path traversal attack.
     *
     * @return true if this is a path traversal-related failure type
     */
    public boolean isPathTraversalAttack() {
        return this == PATH_TRAVERSAL_DETECTED ||
                this == DIRECTORY_ESCAPE_ATTEMPT;
    }

    /**
     * Indicates whether this failure type represents a character-based attack.
     *
     * @return true if this is a character-based failure type
     */
    public boolean isCharacterAttack() {
        return this == INVALID_CHARACTER ||
                this == NULL_BYTE_INJECTION ||
                this == CONTROL_CHARACTERS;
    }

    /**
     * Indicates whether this failure type represents a size or length violation.
     *
     * @return true if this is a size/length-related failure type
     */
    public boolean isSizeViolation() {
        return this == PATH_TOO_LONG ||
                this == INPUT_TOO_LONG ||
                this == EXCESSIVE_NESTING;
    }

    /**
     * Indicates whether this failure type represents a pattern-based detection.
     *
     * @return true if this is a pattern-based failure type
     */
    public boolean isPatternBased() {
        return this == SUSPICIOUS_PATTERN_DETECTED ||
                this == SUSPICIOUS_PARAMETER_NAME ||
                this == KNOWN_ATTACK_SIGNATURE;
    }

    // XSS attack detection removed - application layer responsibility.
    // Application layers have proper context for HTML/JS escaping and validation.

    /**
     * Indicates whether this failure type represents a structural issue.
     *
     * @return true if this is a structural failure type
     */
    public boolean isStructuralIssue() {
        return this == MALFORMED_INPUT ||
                this == INVALID_STRUCTURE;
    }

    /**
     * Indicates whether this failure type represents a protocol violation.
     *
     * @return true if this is a protocol-related failure type
     */
    public boolean isProtocolViolation() {
        return this == PROTOCOL_VIOLATION ||
                this == RFC_VIOLATION;
    }

    /**
     * Indicates whether this failure type represents an IPv6 or host-based attack.
     *
     * @return true if this is an IPv6/host-related failure type
     */
    public boolean isIPv6HostAttack() {
        return this == INVALID_IPV6_FORMAT ||
                this == MALFORMED_URL ||
                this == INVALID_HOST_FORMAT ||
                this == INVALID_URL_FORMAT;
    }
}