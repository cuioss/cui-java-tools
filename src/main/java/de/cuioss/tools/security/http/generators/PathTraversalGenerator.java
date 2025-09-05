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

import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Generator for path traversal attack patterns.
 * 
 * This generator creates various path traversal patterns including:
 * - Basic traversal sequences (../, ..\\)
 * - Encoded variants (%2e%2e%2f, %252e%252e%252f)
 * - Unicode variants (\u002e\u002e\u002f)
 * - Mixed encoding attempts
 * - Null byte injection variants
 * 
 * Based on CVE analysis and OWASP attack patterns from specification.
 * 
 * @author Claude Code Generator
 */
public class PathTraversalGenerator {

    private static final List<String> BASIC_PATTERNS = List.of(
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

    private static final List<String> ENCODED_PATTERNS = List.of(
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

    private static final List<String> UNICODE_PATTERNS = List.of(
            "\\u002e\\u002e\\u002f",
            "\\u002e\\u002e\\u005c",
            "\u002e\u002e\u002f",
            "\u002e\u002e\\",
            "\\u002e\\u002e\\u002f\\u002e\\u002e\\u002f",
            "\\u002e\\u002e\\u005c\\u002e\\u002e\\u005c"
    );

    private static final List<String> MIXED_ENCODING_PATTERNS = List.of(
            "../%2e%2e%2f",
            "..\\%2e%2e%5c",
            "%2e%2e%2f../",
            "%2e%2e%5c..\\",
            "..%c0%af..%c0%af",
            "..%c1%9c..%c1%9c",
            "%c0%ae%c0%ae%c0%af",
            "%c1%8s%c1%8s%c1%81"
    );

    private static final List<String> NULL_BYTE_PATTERNS = List.of(
            "../%00",
            "..\\%00",
            "../../etc/passwd%00.jpg",
            "..\\..\\windows\\win.ini%00.txt",
            "../%00.png",
            "..\\%00.gif",
            "%2e%2e%2f%00",
            "%2e%2e%5c%00"
    );

    private static final List<String> ADVANCED_PATTERNS = List.of(
            "....//....//",
            "....\\\\....\\\\",
            "..;/..;/",
            "..;//..;//",
            "/var/www/../../../etc/passwd",
            "C:\\inetpub\\wwwroot\\..\\..\\Windows\\win.ini",
            "....//....//....//",
            "....\\\\....\\\\....\\\\",
            "..\\../..\\../",
            "../\\../\\../",
            "/%2e%2e/%2e%2e/%2e%2e/",
            "\\\\%2e%2e\\\\%2e%2e\\\\%2e%2e\\\\"
    );

    private final List<List<String>> allPatternGroups;

    public PathTraversalGenerator() {
        this.allPatternGroups = List.of(
                BASIC_PATTERNS,
                ENCODED_PATTERNS,
                UNICODE_PATTERNS,
                MIXED_ENCODING_PATTERNS,
                NULL_BYTE_PATTERNS,
                ADVANCED_PATTERNS
        );
    }

    public String next() {
        ThreadLocalRandom random = ThreadLocalRandom.current();

        // Select a random pattern group
        List<String> selectedGroup = allPatternGroups.get(random.nextInt(allPatternGroups.size()));

        // Select a random pattern from the group
        String basePattern = selectedGroup.get(random.nextInt(selectedGroup.size()));

        // Occasionally add random prefixes/suffixes to make patterns more realistic
        if (random.nextBoolean()) {
            return addRandomContext(basePattern, random);
        }

        return basePattern;
    }

    private String addRandomContext(String basePattern, ThreadLocalRandom random) {
        String[] prefixes = {
                "/api/users/",
                "/admin/",
                "/files/",
                "/uploads/",
                "/documents/",
                "/images/",
                ""
        };

        String[] suffixes = {
                "/sensitive.txt",
                "/config.xml",
                "/database.properties",
                "/secret.key",
                ".conf",
                ".ini",
                ""
        };

        String prefix = prefixes[random.nextInt(prefixes.length)];
        String suffix = suffixes[random.nextInt(suffixes.length)];

        return prefix + basePattern + suffix;
    }

    public Class<String> getType() {
        return String.class;
    }
}