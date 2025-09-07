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
package de.cuioss.tools.security.http.generators;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;

/**
 * Generator for valid URL parameter values.
 * Provides common valid parameter VALUES (not full "name=value" strings) for testing.
 * These values should ALWAYS pass URLParameterValidationPipeline validation.
 */
public class ValidURLParameterStringGenerator implements TypedGenerator<String> {

    private final TypedGenerator<String> validParameters = Generators.fixedValues(
            "123",                    // Simple number
            "java%20programming",     // URL encoded space
            "electronics",           // Simple text
            "1",                     // Single digit
            "50",                    // Number
            "name",                  // Simple text
            "active",               // Status value
            "en",                   // Language code
            "enabled",              // Boolean-like
            "product",              // Type value
            "json",                 // Format
            "v2",                   // Version
            "asc",                  // Order direction
            "10",                   // Size
            "1640995200",          // Timestamp
            "abc123",              // Alphanumeric ID
            "john%2Bdoe",          // URL encoded plus
            "test%40example.com",  // URL encoded email
            "555-1234",            // Phone (no encoding - should be safe)
            "red"                  // Color
    );

    @Override
    public String next() {
        return validParameters.next();
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}