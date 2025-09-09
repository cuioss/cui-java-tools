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
package de.cuioss.tools.security.http.generators.encoding;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;

/**
 * Generator for complex encoding combinations in path traversal attacks.
 * Provides sophisticated mixed encoding patterns for security testing.
 */
public class ComplexEncodingCombinationGenerator implements TypedGenerator<String> {

    private final TypedGenerator<String> complexEncodingPatterns = Generators.fixedValues(
            "/api%2F%2E%2E%2F%2E%2E%2Fadmin%2Fconfig",           // /api/../..admin/config
            "%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd",           // ../../../etc/passwd
            "/files%5C%2E%2E%5C%2E%2E%5Cadmin%5Cconfig",         // \files\..\..\admin\config
            "%252E%252E%252F%252E%252E%252F%252E%252E%252F",     // ../../.. double encoded
            "/path%2F%252E%252E%2F%2E%2E%2Fconfig",              // Mixed single/double encoding
            "%c0%ae%c0%ae%c0%af%2E%2E%2F",                       // UTF-8 overlong + normal encoding
            "/data%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fadmin", // Deep traversal encoded
            "/api%2F%252e%252e%2F%2e%2e%2Fadmin",                // Mixed case double encoding
            "%c0%ae%c0%ae%c0%af%c1%9c%2E%2E%5C",                 // UTF-8 overlong mixed with backslash
            "/system%5C%252E%252E%5C%2E%2E%2Froot",              // Windows + mixed encoding
            "%2E%2E%2F%252e%252e%252f%c0%ae%c0%ae%c0%af",        // Triple encoding combination
            "/backup%2F%2E%2E%5C%252E%252E%2F%2E%2E",            // Mixed slash and backslash encoding
            "%252E%252E%252F%c0%ae%c0%ae%c0%af%2E%2E%5C",        // Double + overlong + backslash
            "/config%2F%2E%2E%2F%252e%252e%5C%2E%2E%2F",         // Complex path with mixed encoding
            "%c1%9c%2E%2E%c1%9c%252E%252E%2F%2E%2E%5C"           // Overlong backslash combinations
    );

    @Override
    public String next() {
        return complexEncodingPatterns.next();
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}