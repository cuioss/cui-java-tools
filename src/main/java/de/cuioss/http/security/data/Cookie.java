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
package de.cuioss.http.security.data;

import de.cuioss.http.security.core.ValidationType;
import org.jspecify.annotations.Nullable;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Immutable record representing an HTTP cookie with name, value, and attributes.
 *
 * <p>This record encapsulates the structure of HTTP cookies as defined in RFC 6265,
 * providing a type-safe way to handle cookie data in HTTP security validation.</p>
 *
 * <h3>Design Principles</h3>
 * <ul>
 *   <li><strong>Immutability</strong> - All fields are final and the record cannot be modified</li>
 *   <li><strong>RFC Compliance</strong> - Follows HTTP cookie specifications</li>
 *   <li><strong>Security Focus</strong> - Designed with security validation in mind</li>
 *   <li><strong>Flexibility</strong> - Supports various cookie attribute formats</li>
 * </ul>
 *
 * <h3>Usage Examples</h3>
 * <pre>
 * // Simple cookie
 * Cookie sessionCookie = new Cookie("JSESSIONID", "ABC123", "");
 *
 * // Cookie with attributes
 * Cookie secureCookie = new Cookie(
 *     "auth_token",
 *     "xyz789",
 *     "Domain=example.com; Path=/; Secure; HttpOnly"
 * );
 *
 * // Access components
 * String name = cookie.name();         // "JSESSIONID"
 * String value = cookie.value();       // "ABC123"
 * String attrs = cookie.attributes();  // "Domain=..."
 *
 * // Check for security attributes
 * boolean isSecure = cookie.isSecure();       // Check for Secure attribute
 * boolean isHttpOnly = cookie.isHttpOnly();   // Check for HttpOnly attribute
 *
 * // Use in validation
 * validator.validate(cookie.name(), ValidationType.COOKIE_NAME);
 * validator.validate(cookie.value(), ValidationType.COOKIE_VALUE);
 * </pre>
 *
 * <h3>Cookie Attributes</h3>
 * <p>The attributes field contains the semicolon-separated list of cookie attributes
 * such as Domain, Path, Secure, HttpOnly, SameSite, and Max-Age. This field can be
 * an empty string if no attributes are present.</p>
 *
 * <h3>Security Considerations</h3>
 * <p>This record is a simple data container. Security validation should be applied
 * to the name, value, and attributes components separately using appropriate validators.</p>
 *
 * Implements: Task B3 from HTTP verification specification
 *
 * @param name The cookie name (e.g., "JSESSIONID", "auth_token")
 * @param value The cookie value (e.g., session ID, authentication token)
 * @param attributes Cookie attributes string (e.g., "Domain=example.com; Secure; HttpOnly")
 *
 * @since 2.5
 * @see ValidationType#COOKIE_NAME
 * @see ValidationType#COOKIE_VALUE
 */
public record Cookie(@Nullable String name, @Nullable String value, @Nullable String attributes) {

    /**
     * Creates a simple cookie with no attributes.
     *
     * @param name The cookie name
     * @param value The cookie value
     * @return A Cookie with no attributes
     */
    public static Cookie simple(String name, String value) {
        return new Cookie(name, value, "");
    }

    /**
     * Checks if this cookie has a non-null, non-empty name.
     *
     * @return true if the name is not null and not empty
     */
    public boolean hasName() {
        return name != null && !name.isEmpty();
    }

    /**
     * Checks if this cookie has a non-null, non-empty value.
     *
     * @return true if the value is not null and not empty
     */
    public boolean hasValue() {
        return value != null && !value.isEmpty();
    }

    /**
     * Checks if this cookie has any attributes.
     *
     * @return true if the attributes string is not null and not empty
     */
    public boolean hasAttributes() {
        return attributes != null && !attributes.isEmpty();
    }

    /**
     * Checks if the cookie has the Secure attribute.
     *
     * @return true if the attributes contain "Secure"
     */
    public boolean isSecure() {
        return hasAttributes() && attributes.toLowerCase().contains("secure");
    }

    /**
     * Checks if the cookie has the HttpOnly attribute.
     *
     * @return true if the attributes contain "HttpOnly"
     */
    public boolean isHttpOnly() {
        return hasAttributes() && attributes.toLowerCase().contains("httponly");
    }

    /**
     * Extracts the Domain attribute value if present.
     *
     * @return The domain value wrapped in Optional, or empty if not specified
     */
    public Optional<String> getDomain() {
        return Optional.ofNullable(extractAttributeValue("domain"));
    }

    /**
     * Extracts the Path attribute value if present.
     *
     * @return The path value wrapped in Optional, or empty if not specified
     */
    public Optional<String> getPath() {
        return Optional.ofNullable(extractAttributeValue("path"));
    }

    /**
     * Extracts the SameSite attribute value if present.
     *
     * @return The SameSite value (e.g., "Strict", "Lax", "None") wrapped in Optional, or empty if not specified
     */
    public Optional<String> getSameSite() {
        return Optional.ofNullable(extractAttributeValue("samesite"));
    }

    /**
     * Extracts the Max-Age attribute value if present.
     *
     * @return The Max-Age value as a string wrapped in Optional, or empty if not specified
     */
    public Optional<String> getMaxAge() {
        return Optional.ofNullable(extractAttributeValue("max-age"));
    }

    /**
     * Extracts a specific attribute value from the attributes string.
     *
     * @param attributeName The name of the attribute (case-insensitive)
     * @return The attribute value or null if not found
     */
    private @Nullable String extractAttributeValue(String attributeName) {
        if (!hasAttributes()) {
            return null;
        }

        String lowerAttrs = attributes.toLowerCase();
        String lowerAttrName = attributeName.toLowerCase();

        // Look for "attributeName=" pattern
        String searchPattern = lowerAttrName + "=";
        int startIndex = lowerAttrs.indexOf(searchPattern);

        if (startIndex == -1) {
            return null;
        }

        // Find the start of the value
        int valueStart = startIndex + searchPattern.length();
        if (valueStart >= attributes.length()) {
            return null;
        }

        // Find the end of the value (semicolon or end of string)
        int valueEnd = attributes.indexOf(';', valueStart);
        if (valueEnd == -1) {
            valueEnd = attributes.length();
        }

        return attributes.substring(valueStart, valueEnd).trim();
    }

    /**
     * Returns all attribute names present in this cookie.
     *
     * @return A list of attribute names (may be empty)
     */
    public List<String> getAttributeNames() {
        if (!hasAttributes()) {
            return List.of();
        }

        return Arrays.stream(attributes.split(";"))
                .map(String::trim)
                .filter(attr -> !attr.isEmpty())
                .map(attr -> {
                    int equalIndex = attr.indexOf('=');
                    return equalIndex > 0 ? attr.substring(0, equalIndex).trim() : attr;
                })
                .collect(Collectors.toList());
    }

    /**
     * Returns the cookie name, or a default value if the name is null.
     *
     * @param defaultName The default name to return if name is null
     * @return The cookie name or the default
     */
    public String nameOrDefault(String defaultName) {
        return name != null ? name : defaultName;
    }

    /**
     * Returns the cookie value, or a default value if the value is null.
     *
     * @param defaultValue The default value to return if value is null
     * @return The cookie value or the default
     */
    public String valueOrDefault(String defaultValue) {
        return value != null ? value : defaultValue;
    }

    /**
     * Returns a string representation suitable for HTTP Set-Cookie headers.
     * Note: This does not perform proper HTTP encoding - use appropriate
     * encoding utilities for actual HTTP header generation.
     *
     * @return A string in the format "name=value; attributes"
     */
    public String toCookieString() {
        StringBuilder sb = new StringBuilder();

        if (name != null) {
            sb.append(name);
        }

        sb.append("=");

        if (value != null) {
            sb.append(value);
        }

        if (hasAttributes()) {
            sb.append("; ").append(attributes);
        }

        return sb.toString();
    }

    /**
     * Returns a copy of this cookie with a new name.
     *
     * @param newName The new cookie name
     * @return A new Cookie with the specified name and same value/attributes
     */
    public Cookie withName(String newName) {
        return new Cookie(newName, value, attributes);
    }

    /**
     * Returns a copy of this cookie with a new value.
     *
     * @param newValue The new cookie value
     * @return A new Cookie with the same name/attributes and specified value
     */
    public Cookie withValue(String newValue) {
        return new Cookie(name, newValue, attributes);
    }

    /**
     * Returns a copy of this cookie with new attributes.
     *
     * @param newAttributes The new attributes string
     * @return A new Cookie with the same name/value and specified attributes
     */
    public Cookie withAttributes(String newAttributes) {
        return new Cookie(name, value, newAttributes);
    }
}