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
package de.cuioss.tools.security.http.generators.url;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;

/**
 * Generator for URL parameter values containing path traversal attacks.
 *
 * <p>QI-6: Converted from fixedValues() to dynamic algorithmic generation.</p>
 *
 * Provides parameter VALUES (not full "name=value" strings) with various path traversal patterns.
 * These values are designed to be detected by URLParameterValidationPipeline.
 */
public class PathTraversalParameterGenerator implements TypedGenerator<String> {

    // QI-6: Dynamic generation components
    private final TypedGenerator<Integer> attackTypeGen = Generators.integers(1, 8);
    private final TypedGenerator<Integer> depthGen = Generators.integers(1, 4);
    private final TypedGenerator<String> targetFileGen = Generators.fixedValues("etc/passwd", "config", "windows", "root", "shadow", "etc/hosts", "boot.ini", "var/log/auth.log", "windows/system32/config/sam", "root/.ssh/id_rsa");
    private final TypedGenerator<Integer> pathSepSelector = Generators.integers(1, 2);
    private final TypedGenerator<Boolean> caseVariationGen = Generators.booleans();

    @Override
    public String next() {
        return switch (attackTypeGen.next()) {
            case 1 -> generateBasicEncodedTraversal();
            case 2 -> generateDoubleEncodedTraversal();
            case 3 -> generateMixedEncodingTraversal();
            case 4 -> generateWindowsStyleTraversal();
            case 5 -> generateDeepTraversal();
            case 6 -> generateQuadDotBypass();
            case 7 -> generateUtf8OverlongTraversal();
            case 8 -> generateTripleEncodedTraversal();
            default -> generateBasicEncodedTraversal();
        };
    }

    private String generateBasicEncodedTraversal() {
        int depth = depthGen.next();
        String targetFile = targetFileGen.next();
        StringBuilder pattern = new StringBuilder();

        for (int i = 0; i < depth; i++) {
            pattern.append("..%2F");
        }

        // Encode the target file path
        String encodedTarget = targetFile.replace("/", "%2F");
        pattern.append(encodedTarget);

        return pattern.toString();
    }

    private String generateDoubleEncodedTraversal() {
        int depth = depthGen.next();
        String targetFile = targetFileGen.next();
        StringBuilder pattern = new StringBuilder();

        for (int i = 0; i < depth; i++) {
            pattern.append("%2E%2E%2F");
        }

        String encodedTarget = targetFile.replace("/", "%2F");
        pattern.append(encodedTarget);

        return pattern.toString();
    }

    private String generateMixedEncodingTraversal() {
        int depth = depthGen.next();
        String targetFile = targetFileGen.next();
        StringBuilder pattern = new StringBuilder();

        for (int i = 0; i < depth; i++) {
            if (caseVariationGen.next()) {
                pattern.append("%2e%2e%2f"); // Lowercase
            } else {
                pattern.append("%2E%2E%2F"); // Uppercase
            }
        }

        String encodedTarget = targetFile.replace("/", "%2f");
        pattern.append(encodedTarget);

        return pattern.toString();
    }

    private String generateWindowsStyleTraversal() {
        int depth = depthGen.next();
        String targetFile = targetFileGen.next();
        StringBuilder pattern = new StringBuilder();

        for (int i = 0; i < depth; i++) {
            if (caseVariationGen.next()) {
                pattern.append("..%5c"); // Mixed with unencoded
            } else {
                pattern.append("%2e%2e%5c"); // Fully encoded
            }
        }

        String encodedTarget = targetFile.replace("/", "%5c").replace("\\", "%5c");
        pattern.append(encodedTarget);

        return pattern.toString();
    }

    private String generateDeepTraversal() {
        String targetFile = targetFileGen.next();
        StringBuilder pattern = new StringBuilder();

        // Generate deep path (3-6 levels)
        int deepDepth = Generators.integers(3, 6).next();
        for (int i = 0; i < deepDepth; i++) {
            pattern.append("%2e%2e%2f");
        }

        String encodedTarget = targetFile.replace("/", "%2f");
        pattern.append(encodedTarget);

        return pattern.toString();
    }

    private String generateQuadDotBypass() {
        int depth = depthGen.next();
        String targetFile = targetFileGen.next();
        StringBuilder pattern = new StringBuilder();

        // Use quad-dots as bypass technique
        for (int i = 0; i < depth; i++) {
            pattern.append("....%2f");
        }

        String encodedTarget = targetFile.replace("/", "%2f");
        pattern.append(encodedTarget);

        return pattern.toString();
    }

    private String generateUtf8OverlongTraversal() {
        int depth = depthGen.next();
        String targetFile = targetFileGen.next();
        StringBuilder pattern = new StringBuilder();

        for (int i = 0; i < depth; i++) {
            if (caseVariationGen.next()) {
                pattern.append("..%c0%af"); // UTF-8 overlong slash variant 1
            } else {
                pattern.append("%c0%ae%c0%ae%c0%af"); // UTF-8 overlong dots + slash variant 2
            }
        }

        String encodedTarget = targetFile.replace("/", "%c0%af");
        pattern.append(encodedTarget);

        return pattern.toString();
    }

    private String generateTripleEncodedTraversal() {
        int depth = depthGen.next();
        String targetFile = targetFileGen.next();
        StringBuilder pattern = new StringBuilder();

        // Triple URL encoding (%252e = double encoded %2e)
        for (int i = 0; i < depth; i++) {
            pattern.append("%252e%252e%252f");
        }

        String encodedTarget = targetFile.replace("/", "%252f");
        pattern.append(encodedTarget);

        return pattern.toString();
    }

    private String generatePathSeparator() {
        return switch (pathSepSelector.next()) {
            case 1 -> "/";
            case 2 -> "\\";
            default -> "/";
        };
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}