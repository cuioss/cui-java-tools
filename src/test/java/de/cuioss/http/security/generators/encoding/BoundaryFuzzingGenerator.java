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
package de.cuioss.http.security.generators.encoding;

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
        StringBuilder path = new StringBuilder();
        for (int i = 0; i < depth; i++) {
            path.append("dir/");
        }
        return path.toString();
    }

    private String generateNullBytes() {
        int patternType = Generators.integers(0, 4).next();
        return switch (patternType) {
            case 0 -> "/file\u0000.txt";              // Raw null byte
            case 1 -> "/admin%00.php";                // Encoded null byte
            case 2 -> "../etc/passwd%00.jpg";         // Path traversal with null
            case 3 -> "file.jsp%00.png";              // Extension bypass
            case 4 -> "%00../../etc/shadow";          // Leading null byte
            default -> "/file\u0000.txt";
        };
    }

    private String generateControlCharacters() {
        // Various control characters that should be rejected
        int controlType = Generators.integers(0, 3).next();
        return switch (controlType) {
            case 0 -> "/file\r\n.txt";                // CRLF injection
            case 1 -> "/path\t\tfile";                // Tab characters
            case 2 -> "/dir\b\bfile";                 // Backspace
            case 3 -> "/test\u001Ffile";              // Unit separator
            default -> "/file\r\n.txt";
        };
    }

    private String generateMixedBoundaryAttacks() {
        // Combine multiple boundary issues
        TypedGenerator<Integer> attackGen = Generators.integers(0, 3);
        int attack = attackGen.next();
        return switch (attack) {
            case 0 -> generateTraversalPattern() + "etc/passwd";  // QI-17: Dynamic traversal
            case 1 -> "/a" + generatePathSegmentPattern();        // QI-17: Dynamic path segments
            case 2 -> "/%00" + generateTraversalPattern();        // QI-17: Dynamic null + traversal
            default -> "/\u0000/../\u0000/../file";       // Multiple nulls
        };
    }

    private String generateSpecialChars() {
        // Other special characters
        int specialType = Generators.integers(0, 4).next();
        return switch (specialType) {
            case 0 -> "/file|command";                // Pipe character
            case 1 -> "/file;command";                // Semicolon
            case 2 -> "/file`command`";               // Backticks
            case 3 -> "/file$variable";               // Variable expansion
            case 4 -> "/file>output";                 // Redirection
            default -> "/file|command";
        };
    }

    // QI-17: Dynamic generation helpers to replace hardcoded .repeat() patterns
    private String generateTraversalPattern() {
        int depth = Generators.integers(15, 25).next(); // Reasonable traversal depth
        StringBuilder pattern = new StringBuilder();
        for (int i = 0; i < depth; i++) {
            pattern.append("../");
        }
        return pattern.toString();
    }

    private String generatePathSegmentPattern() {
        int segments = Generators.integers(50, 80).next(); // Increased to exceed 1000 chars
        StringBuilder pattern = new StringBuilder();
        for (int i = 0; i < segments; i++) {
            pattern.append("verylongpathsegment/");
        }
        return pattern.toString();
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}