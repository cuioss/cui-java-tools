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

    public CharacterValidationStage(SecurityConfiguration config, ValidationType type) {
        this.validationType = type;
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
            if (ch == '\0') {
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
                if (hex1 == '0' && hex2 == '0') {
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

            // Check if character is allowed
            if (ch > 255 || !allowedChars.get(ch)) {
                throw UrlSecurityException.builder()
                        .failureType(UrlSecurityFailureType.INVALID_CHARACTER)
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
}