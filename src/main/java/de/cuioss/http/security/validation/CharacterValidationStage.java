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
import de.cuioss.http.security.core.HttpSecurityValidator;
import de.cuioss.http.security.core.UrlSecurityFailureType;
import de.cuioss.http.security.core.ValidationType;
import de.cuioss.http.security.exceptions.UrlSecurityException;
import lombok.EqualsAndHashCode;
import lombok.ToString;

import java.util.BitSet;

/**
 * Validates characters according to RFC 3986 for URLs.
 * MUST be the second stage after length validation.
 * Rejects invalid characters BEFORE any decoding/processing.
 * Immutable and thread-safe.
 * Implemented by: Task V5
 */
@EqualsAndHashCode
@ToString
public final class CharacterValidationStage implements HttpSecurityValidator {

    private final BitSet allowedChars;
    private final ValidationType validationType;
    private final boolean allowPercentEncoding;
    private final boolean allowNullBytes;
    private final boolean allowControlCharacters;
    private final boolean allowHighBitCharacters;

    public CharacterValidationStage(SecurityConfiguration config, ValidationType type) {
        this.validationType = type;
        this.allowNullBytes = config.allowNullBytes();
        this.allowControlCharacters = config.allowControlCharacters();
        this.allowHighBitCharacters = config.allowHighBitCharacters();
        // Use the shared BitSet directly - it's read-only after initialization
        this.allowedChars = CharacterValidationConstants.getCharacterSet(type);

        // Determine if percent encoding is allowed based on type
        this.allowPercentEncoding = switch (type) {
            case URL_PATH, PARAMETER_NAME, PARAMETER_VALUE -> true;
            default -> false;  // HEADER_NAME, HEADER_VALUE and others don't allow percent encoding
        };
    }

    @Override
    public String validate(String value) throws UrlSecurityException {
        // Quick check for null/empty
        if (value == null || value.isEmpty()) {
            return value;
        }

        // Check each character
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);

            // Check for null byte FIRST (highest priority security check)
            if (ch == '\0' && !allowNullBytes) {
                throw UrlSecurityException.builder()
                        .failureType(UrlSecurityFailureType.NULL_BYTE_INJECTION)
                        .validationType(validationType)
                        .originalInput(value)
                        .detail("Null byte detected at position " + i)
                        .build();
            }

            // Handle percent encoding
            if (ch == '%' && allowPercentEncoding) {
                // Must be followed by two hex digits
                if (i + 2 >= value.length()) {
                    throw UrlSecurityException.builder()
                            .failureType(UrlSecurityFailureType.INVALID_ENCODING)
                            .validationType(validationType)
                            .originalInput(value)
                            .detail("Incomplete percent encoding at position " + i)
                            .build();
                }

                char hex1 = value.charAt(i + 1);
                char hex2 = value.charAt(i + 2);
                if (isNotHexDigit(hex1) || isNotHexDigit(hex2)) {
                    throw UrlSecurityException.builder()
                            .failureType(UrlSecurityFailureType.INVALID_ENCODING)
                            .validationType(validationType)
                            .originalInput(value)
                            .detail("Invalid hex digits in percent encoding at position " + i)
                            .build();
                }

                // Check for encoded null byte %00
                if (hex1 == '0' && hex2 == '0' && !allowNullBytes) {
                    throw UrlSecurityException.builder()
                            .failureType(UrlSecurityFailureType.NULL_BYTE_INJECTION)
                            .validationType(validationType)
                            .originalInput(value)
                            .detail("Encoded null byte (%00) detected at position " + i)
                            .build();
                }

                i += 2; // Skip the two hex digits
                continue;
            }

            // Check if character is allowed based on configuration and character sets
            if (!isCharacterAllowed(ch)) {
                UrlSecurityFailureType failureType = getFailureTypeForCharacter(ch);
                throw UrlSecurityException.builder()
                        .failureType(failureType)
                        .validationType(validationType)
                        .originalInput(value)
                        .detail("Invalid character '" + ch + "' (0x" + Integer.toHexString(ch).toUpperCase() + ") at position " + i)
                        .build();
            }
        }

        return value;
    }

    private boolean isNotHexDigit(char ch) {
        return !((ch >= '0' && ch <= '9') ||
                (ch >= 'A' && ch <= 'F') ||
                (ch >= 'a' && ch <= 'f'));
    }

    /**
     * Checks if a character is allowed based on configuration flags and character sets.
     */
    private boolean isCharacterAllowed(char ch) {
        // Null byte (0) - should be allowed if configured (already checked earlier but may reach here)
        if (ch == 0) {
            return allowNullBytes;
        }

        // Control characters (1-31, excluding null which is handled above)
        if (ch >= 1 && ch <= 31) {
            // Always allow common whitespace characters that are in the base character set
            if (allowedChars.get(ch)) {
                return true;
            }
            // Other control characters depend on configuration
            return allowControlCharacters;
        }

        // Characters 32-127 (basic ASCII) - check against the base character set
        if (ch >= 32 && ch <= 127) {
            return allowedChars.get(ch);
        }

        // Extended ASCII characters (128-255) - check configuration and base character set
        if (ch >= 128 && ch <= 255) {
            return allowHighBitCharacters || allowedChars.get(ch);
        }

        // Unicode characters above 255 - allow only if high-bit characters are allowed
        // and the validation type supports it (e.g., BODY content is more permissive than URL paths)
        if (ch > 255) {
            // Always reject combining characters (U+0300-U+036F) as they can cause normalization issues
            if (ch >= 0x0300 && ch <= 0x036F) {
                return false;
            }
            return allowHighBitCharacters && supportsUnicodeCharacters();
        }

        // This should not be reached, but default to false for safety
        return false;
    }

    /**
     * Determines the appropriate failure type for a rejected character.
     */
    private UrlSecurityFailureType getFailureTypeForCharacter(char ch) {
        // Null byte (0)
        if (ch == 0) {
            return UrlSecurityFailureType.NULL_BYTE_INJECTION;
        }

        // Control characters (1-31)
        if (ch >= 1 && ch <= 31) {
            // For headers, control characters are just invalid characters per RFC
            // For other contexts, they're specifically flagged as control characters for security
            if (validationType == ValidationType.HEADER_NAME || validationType == ValidationType.HEADER_VALUE) {
                return UrlSecurityFailureType.INVALID_CHARACTER;
            }
            // If it's in the base character set, it's just an invalid character for this context
            if (allowedChars.get(ch)) {
                return UrlSecurityFailureType.INVALID_CHARACTER;
            }
            return UrlSecurityFailureType.CONTROL_CHARACTERS;
        }

        // High-bit characters (128-255) and Unicode characters (> 255)
        if (ch >= 128) {
            return UrlSecurityFailureType.INVALID_CHARACTER;
        }

        // All other invalid characters
        return UrlSecurityFailureType.INVALID_CHARACTER;
    }

    /**
     * Determines if the current validation type supports Unicode characters beyond 255.
     * URL paths and parameter validation are more restrictive per RFC 3986,
     * while body and header content can be more permissive.
     */
    private boolean supportsUnicodeCharacters() {
        return switch (validationType) {
            case BODY -> true;  // Body content can contain Unicode
            case HEADER_VALUE -> true;  // Header values can contain Unicode in some cases
            case URL_PATH, PARAMETER_NAME, PARAMETER_VALUE -> false;  // RFC 3986 is ASCII-based
            case HEADER_NAME -> false;  // Header names should be ASCII
            case COOKIE_NAME, COOKIE_VALUE -> false;  // Cookies should be ASCII-safe
        };
    }
}