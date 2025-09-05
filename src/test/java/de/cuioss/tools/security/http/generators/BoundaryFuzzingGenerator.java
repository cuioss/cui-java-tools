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
 * Generates boundary condition test cases.
 * Implements: Task G4 from HTTP verification specification
 */
public class BoundaryFuzzingGenerator implements TypedGenerator<String> {

    private final TypedGenerator<Integer> lengthGen = Generators.integers(1000, 10000);
    private final TypedGenerator<Integer> nestingGen = Generators.integers(50, 200);
    private final TypedGenerator<Integer> typeGen = Generators.integers(0, 5);

    @Override
    public String next() {
        int type = typeGen.next();

        return switch (type) {
            case 0 -> generateLongPath();
            case 1 -> generateDeepNesting();
            case 2 -> generateNullBytes();
            case 3 -> generateControlCharacters();
            case 4 -> generateMixedBoundaryAttacks();
            default -> generateSpecialChars();
        };
    }

    private String generateLongPath() {
        int length = lengthGen.next();
        StringBuilder path = new StringBuilder("/");
        while (path.length() < length) {
            path.append("verylongpathsegment/");
        }
        return path.toString();
    }

    private String generateDeepNesting() {
        int depth = nestingGen.next();
        return "dir/".repeat(depth);
    }

    private String generateNullBytes() {
        TypedGenerator<String> patterns = Generators.fixedValues(
                "/file\u0000.txt",              // Raw null byte
                "/admin%00.php",                // Encoded null byte
                "../etc/passwd%00.jpg",         // Path traversal with null
                "file.jsp%00.png",              // Extension bypass
                "%00../../etc/shadow"           // Leading null byte
        );
        return patterns.next();
    }

    private String generateControlCharacters() {
        // Various control characters that should be rejected
        TypedGenerator<String> controls = Generators.fixedValues(
                "/file\r\n.txt",                // CRLF injection
                "/path\t\tfile",                // Tab characters
                "/dir\b\bfile",                 // Backspace
                "/test\u001Ffile"               // Unit separator
        );
        return controls.next();
    }

    private String generateMixedBoundaryAttacks() {
        // Combine multiple boundary issues
        TypedGenerator<Integer> attackGen = Generators.integers(0, 3);
        int attack = attackGen.next();
        return switch (attack) {
            case 0 -> "../".repeat(100) + "etc/passwd";  // Excessive traversal
            case 1 -> "/a".repeat(2000);                  // Near max length
            case 2 -> "/%00" + "../".repeat(10);          // Null + traversal
            default -> "/\u0000/../\u0000/../file";       // Multiple nulls
        };
    }

    private String generateSpecialChars() {
        // Other special characters
        TypedGenerator<String> specials = Generators.fixedValues(
                "/file|command",                // Pipe character
                "/file;command",                // Semicolon
                "/file`command`",               // Backticks
                "/file$variable",               // Variable expansion
                "/file>output"                  // Redirection
        );
        return specials.next();
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}