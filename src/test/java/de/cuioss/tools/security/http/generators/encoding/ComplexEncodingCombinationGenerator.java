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
 * 
 * <p>QI-6: Converted from fixedValues() to dynamic algorithmic generation.</p>
 * 
 * Provides sophisticated mixed encoding patterns for security testing.
 */
public class ComplexEncodingCombinationGenerator implements TypedGenerator<String> {

    // QI-6: Dynamic generation components
    private final TypedGenerator<Integer> complexityTypeGen = Generators.integers(1, 6);
    private final TypedGenerator<String> basePathGen = Generators.fixedValues("api", "files", "data", "system", "backup", "config");
    private final TypedGenerator<String> targetGen = Generators.fixedValues("admin/config", "etc/passwd", "admin", "root", "config");
    private final TypedGenerator<Integer> depthGen = Generators.integers(2, 5);
    private final TypedGenerator<Boolean> useWindowsStyleGen = Generators.booleans();
    private final TypedGenerator<Boolean> mixedCaseGen = Generators.booleans();

    @Override
    public String next() {
        return switch (complexityTypeGen.next()) {
            case 1 -> generateMixedSingleDoubleEncoding();
            case 2 -> generateUtf8OverlongCombination();
            case 3 -> generateWindowsMixedEncoding();
            case 4 -> generateTripleEncodingCombination();
            case 5 -> generateComplexPathEncoding();
            case 6 -> generateDeepTraversalEncoding();
            default -> generateMixedSingleDoubleEncoding();
        };
    }

    private String generateMixedSingleDoubleEncoding() {
        String basePath = basePathGen.next();
        String target = targetGen.next();
        int depth = depthGen.next();

        StringBuilder pattern = new StringBuilder("/" + basePath + "%2F");

        // Mix single and double encoding for traversal
        for (int i = 0; i < depth; i++) {
            if (i % 2 == 0) {
                pattern.append("%2E%2E%2F"); // Single encoded
            } else {
                pattern.append("%252E%252E%252F"); // Double encoded
            }
        }

        pattern.append(target.replace("/", "%2F"));
        return pattern.toString();
    }

    private String generateUtf8OverlongCombination() {
        String basePath = basePathGen.next();
        String target = targetGen.next();
        int depth = depthGen.next();

        StringBuilder pattern = new StringBuilder();

        // Start with overlong UTF-8 sequences
        for (int i = 0; i < depth; i++) {
            if (i % 2 == 0) {
                pattern.append("%c0%ae%c0%ae%c0%af"); // UTF-8 overlong ../
            } else {
                pattern.append("%2E%2E%2F"); // Normal encoded
            }
        }

        // Add target with mixed encoding
        pattern.append(target.replace("/", "%2F"));
        return pattern.toString();
    }

    private String generateWindowsMixedEncoding() {
        String basePath = basePathGen.next();
        String target = targetGen.next();
        int depth = depthGen.next();

        StringBuilder pattern = new StringBuilder("/" + basePath);

        // Use Windows-style backslashes with mixed encoding
        for (int i = 0; i < depth; i++) {
            if (i % 2 == 0) {
                pattern.append("%5C%2E%2E"); // Encoded backslash ..
            } else {
                pattern.append("%5C%252E%252E"); // Mixed encoding
            }
        }

        pattern.append("%5C").append(target.replace("/", "%5C"));
        return pattern.toString();
    }

    private String generateTripleEncodingCombination() {
        String target = targetGen.next();
        int depth = depthGen.next();

        StringBuilder pattern = new StringBuilder();

        // Combine single, double, and overlong encoding
        for (int i = 0; i < depth; i++) {
            int encodingType = i % 3;
            switch (encodingType) {
                case 0 -> pattern.append("%2E%2E%2F"); // Single
                case 1 -> pattern.append("%252E%252E%252F"); // Double
                case 2 -> pattern.append("%c0%ae%c0%ae%c0%af"); // Overlong
            }
        }

        pattern.append(target.replace("/", "%2f"));
        return pattern.toString();
    }

    private String generateComplexPathEncoding() {
        String basePath = basePathGen.next();
        String target = targetGen.next();
        boolean useWindows = useWindowsStyleGen.next();

        StringBuilder pattern = new StringBuilder("/" + basePath + "%2F");

        // Complex mixed encoding with both slashes and backslashes
        pattern.append("%2E%2E");
        if (useWindows) {
            pattern.append("%5C%252E%252E%2F");
        } else {
            pattern.append("%2F%252e%252e%5C");
        }
        pattern.append("%2E%2E%2F");

        pattern.append(target.replace("/", "%2F"));
        return pattern.toString();
    }

    private String generateDeepTraversalEncoding() {
        String basePath = basePathGen.next();
        String target = targetGen.next();

        StringBuilder pattern = new StringBuilder("/" + basePath + "%2F");

        // Generate deep traversal with 4-6 levels
        int deepDepth = Generators.integers(4, 6).next();
        for (int i = 0; i < deepDepth; i++) {
            if (mixedCaseGen.next()) {
                pattern.append("%2e%2e%2f"); // Lowercase
            } else {
                pattern.append("%2E%2E%2F"); // Uppercase
            }
        }

        pattern.append(target.replace("/", "%2F"));
        return pattern.toString();
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}