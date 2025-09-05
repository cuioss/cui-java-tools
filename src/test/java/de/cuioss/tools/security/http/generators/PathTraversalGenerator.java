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
 * Generator for path traversal attack patterns.
 * 
 * This generator creates various path traversal patterns including:
 * - Basic traversal sequences (../, ..\\)
 * - Encoded variants (%2e%2e%2f, %252e%252e%252f)
 * - Unicode variants (\\u002e\\u002e\\u002f)
 * - Mixed encoding attempts
 * - Null byte injection variants
 * 
 * Based on CVE analysis and OWASP attack patterns from specification.
 * 
 * @author Claude Code Generator
 */
public class PathTraversalGenerator implements TypedGenerator<String> {

    private final TypedGenerator<String> basicPatterns = Generators.fixedValues(
            "../",
            "..\\",
            "../../",
            "..\\..\\",
            "../../../",
            "..\\..\\..\\",
            "../../../../",
            "..\\..\\..\\..\\",
            "../../../../../",
            "..\\..\\..\\..\\..\\",
            "../../../../../../",
            "..\\..\\..\\..\\..\\..\\",
            "../../../../../../../etc/passwd",
            "..\\..\\..\\..\\..\\..\\..\\windows\\win.ini"
    );

    private final TypedGenerator<String> encodedPatterns = Generators.fixedValues(
            "%2e%2e%2f",
            "%2e%2e%5c",
            "%2e%2e%2f%2e%2e%2f",
            "%2e%2e%5c%2e%2e%5c",
            "%252e%252e%252f",
            "%252e%252e%255c",
            "%252e%252e%252f%252e%252e%252f",
            "..%2f",
            "..%5c",
            "..%252f",
            "..%255c",
            "%2e%2e%2fetc%2fpasswd",
            "%2e%2e%5cwindows%5cwin.ini"
    );

    private final TypedGenerator<String> unicodePatterns = Generators.fixedValues(
            "\\u002e\\u002e\\u002f",
            "\\u002e\\u002e\\u005c",
            "\u002e\u002e\u002f",
            "\u002e\u002e\\",
            "\\u002e\\u002e\\u002f\\u002e\\u002e\\u002f",
            "\\u002e\\u002e\\u005c\\u002e\\u002e\\u005c"
    );

    private final TypedGenerator<String> mixedEncodingPatterns = Generators.fixedValues(
            "../%2e%2e%2f",
            "..\\%2e%2e%5c",
            "%2e%2e%2f../",
            "%2e%2e%5c..\\",
            "..%c0%af..%c0%af",
            "..%c1%9c..%c1%9c",
            "%c0%ae%c0%ae%c0%af",
            "%c1%8s%c1%8s%c1%81"
    );

    private final TypedGenerator<String> nullBytePatterns = Generators.fixedValues(
            "../%00",
            "..\\%00",
            "../../etc/passwd%00.jpg",
            "..\\..\\windows\\win.ini%00.txt",
            "../%00.png",
            "..\\%00.gif",
            "%2e%2e%2f%00",
            "%2e%2e%5c%00"
    );

    private final TypedGenerator<String> advancedPatterns = Generators.fixedValues(
            "....//....//",
            "....\\\\....\\\\",
            "..//..//",
            "..\\\\..\\\\",
            "/var/www/../../../etc/passwd",
            "C:\\inetpub\\wwwroot\\..\\..\\Windows\\win.ini",
            "....//....//....//",
            "....\\\\....\\\\....\\\\",
            "..\\../..\\../",
            "../\\../\\../",
            "/%2e%2e/%2e%2e/%2e%2e/",
            "\\\\%2e%2e\\\\%2e%2e\\\\%2e%2e\\\\"
    );

    private final TypedGenerator<TypedGenerator<String>> patternGroupSelector = Generators.fixedValues(
            basicPatterns,
            encodedPatterns,
            unicodePatterns,
            mixedEncodingPatterns,
            nullBytePatterns,
            advancedPatterns
    );

    private final TypedGenerator<Boolean> contextSelector = Generators.booleans();

    private final TypedGenerator<String> prefixSelector = Generators.fixedValues(
            "/api/users/",
            "/admin/",
            "/files/",
            "/uploads/",
            "/documents/",
            "/images/",
            ""
    );

    private final TypedGenerator<String> suffixSelector = Generators.fixedValues(
            "/sensitive.txt",
            "/config.xml",
            "/database.properties",
            "/secret.key",
            ".conf",
            ".ini",
            ""
    );

    @Override
    public String next() {
        // Select a random pattern group generator
        TypedGenerator<String> selectedPatternGenerator = patternGroupSelector.next();

        // Get a pattern from the selected group
        String basePattern = selectedPatternGenerator.next();

        // Occasionally add random prefixes/suffixes to make patterns more realistic
        if (contextSelector.next()) {
            return addRandomContext(basePattern);
        }

        return basePattern;
    }

    private String addRandomContext(String basePattern) {
        String prefix = prefixSelector.next();
        String suffix = suffixSelector.next();

        return prefix + basePattern + suffix;
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}