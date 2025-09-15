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

/**
 * Immutable record representing a URL query parameter with name and value.
 *
 * <p>This record encapsulates the key-value pair structure of URL query parameters,
 * providing a type-safe way to handle parameter data in HTTP security validation.</p>
 *
 * <h3>Design Principles</h3>
 * <ul>
 *   <li><strong>Immutability</strong> - All fields are final and the record cannot be modified</li>
 *   <li><strong>Type Safety</strong> - Strongly typed representation of parameter data</li>
 *   <li><strong>Null Safety</strong> - Explicit handling of null values with clear semantics</li>
 *   <li><strong>Value Semantics</strong> - Records provide automatic equals/hashCode/toString</li>
 * </ul>
 *
 * <h3>Usage Examples</h3>
 * <pre>
 * // Create a parameter
 * URLParameter param = new URLParameter("userId", "12345");
 *
 * // Access components
 * String name = param.name();     // "userId"
 * String value = param.value();   // "12345"
 *
 * // Use in validation
 * validator.validate(param.name(), ValidationType.PARAMETER_NAME);
 * validator.validate(param.value(), ValidationType.PARAMETER_VALUE);
 *
 * // Parameters are value objects
 * URLParameter param2 = new URLParameter("userId", "12345");
 * assert param.equals(param2);  // true
 * </pre>
 *
 * <h3>Null Handling</h3>
 * <p>Both name and value can be null to represent edge cases in HTTP parsing,
 * though null parameter names are typically invalid in well-formed URLs.</p>
 *
 * <h3>Security Considerations</h3>
 * <p>This record is a simple data container. Security validation should be applied
 * to the name and value components separately using appropriate validators for
 * {@link ValidationType#PARAMETER_NAME} and {@link ValidationType#PARAMETER_VALUE}.</p>
 *
 * Implements: Task B3 from HTTP verification specification
 *
 * @param name The parameter name (e.g., "userId", "page", "filter")
 * @param value The parameter value (e.g., "12345", "admin", "active")
 *
 * @since 2.5
 * @see ValidationType#PARAMETER_NAME
 * @see ValidationType#PARAMETER_VALUE
 */
public record URLParameter(@Nullable String name, @Nullable String value) {

    /**
     * Creates a URLParameter with empty value.
     * Useful for parameters that appear without values (e.g., "?flag" instead of "?flag=value").
     *
     * @param name The parameter name, should not be null
     * @return A URLParameter with the specified name and empty string value
     */
    public static URLParameter withEmptyValue(String name) {
        return new URLParameter(name, "");
    }

    /**
     * Checks if this parameter has a non-null, non-empty name.
     *
     * @return true if the name is not null and not empty
     */
    public boolean hasName() {
        return name != null && !name.isEmpty();
    }

    /**
     * Checks if this parameter has a non-null, non-empty value.
     *
     * @return true if the value is not null and not empty
     */
    public boolean hasValue() {
        return value != null && !value.isEmpty();
    }

    /**
     * Checks if this parameter represents a flag (has name but no meaningful value).
     * A parameter is considered a flag if it has a name but the value is null or empty.
     *
     * @return true if this appears to be a flag parameter
     */
    public boolean isFlag() {
        return hasName() && (value == null || value.isEmpty());
    }

    /**
     * Returns the parameter name, or a default value if the name is null.
     *
     * @param defaultName The default name to return if name is null
     * @return The parameter name or the default
     */
    public String nameOrDefault(String defaultName) {
        return name != null ? name : defaultName;
    }

    /**
     * Returns the parameter value, or a default value if the value is null.
     *
     * @param defaultValue The default value to return if value is null
     * @return The parameter value or the default
     */
    public String valueOrDefault(String defaultValue) {
        return value != null ? value : defaultValue;
    }

    /**
     * Returns a string representation suitable for URL encoding.
     * Note: This does not perform actual URL encoding - use appropriate
     * encoding utilities for that purpose.
     *
     * @return A string in the format "name=value" or "name" for flag parameters
     */
    public String toParameterString() {
        if (name == null) {
            return value != null ? "=" + value : "";
        }
        if (value == null || value.isEmpty()) {
            return name;
        }
        return name + "=" + value;
    }

    /**
     * Returns a copy of this parameter with a new name.
     *
     * @param newName The new parameter name
     * @return A new URLParameter with the specified name and the same value
     */
    public URLParameter withName(String newName) {
        return new URLParameter(newName, value);
    }

    /**
     * Returns a copy of this parameter with a new value.
     *
     * @param newValue The new parameter value
     * @return A new URLParameter with the same name and the specified value
     */
    public URLParameter withValue(String newValue) {
        return new URLParameter(name, newValue);
    }
}