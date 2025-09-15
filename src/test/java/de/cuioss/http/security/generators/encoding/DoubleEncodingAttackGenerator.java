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
 * Generates double and multiple encoding attack patterns.
 *
 * <p>QI-6: Converted from fixedValues() to dynamic algorithmic generation.</p>
 *
 * Focuses specifically on double encoding bypass techniques for security testing.
 *
 * Implements: Task G5 from HTTP verification specification
 */
public class DoubleEncodingAttackGenerator implements TypedGenerator<String> {

    // QI-6: Dynamic generation components
    private final TypedGenerator<Integer> encodingTypeGen = Generators.integers(1, 8);
    private final TypedGenerator<Integer> depthGen = Generators.integers(1, 6);
    private final TypedGenerator<Integer> pathPrefixSelector = Generators.integers(1, 6);
    private final TypedGenerator<Integer> targetFileSelector = Generators.integers(1, 6);

    @Override
    public String next() {
        int encodingType = encodingTypeGen.next();

        return switch (encodingType) {
            case 1 -> generateClassicDoubleEncoding();
            case 2 -> generateApacheCVEDoubleEncoding();
            case 3 -> generateMixedSingleDoubleEncoding();
            case 4 -> generateTripleEncoding();
            case 5 -> generateCaseVariationDoubleEncoding();
            case 6 -> generateWindowsDoubleEncoding();
            case 7 -> generateLegitimatePathDoubleEncoding();
            case 8 -> generateDeepDoubleEncoding();
            default -> generateClassicDoubleEncoding();
        };
    }

    private String generateClassicDoubleEncoding() {
        int depth = depthGen.next();
        StringBuilder pattern = new StringBuilder();

        for (int i = 0; i < depth; i++) {
            pattern.append("%252e%252e%252f");
        }

        if (Generators.booleans().next()) {
            pattern.append("etc/").append(generateTargetFile());
        }

        return pattern.toString();
    }

    private String generateApacheCVEDoubleEncoding() {
        String[] cvePatterns = {
                "%%32%65",  // %2e double encoded
                "%%32%66",  // %2f double encoded
                "/icons%%32%65%%32%65/etc/" + generateTargetFile(),
                "/cgi-bin/.%%32%65/%%32%65%%32%65/etc/" + generateTargetFile()
        };
        return cvePatterns[Generators.integers(0, 3).next()];
    }

    private String generateMixedSingleDoubleEncoding() {
        String target = generateTargetFile();
        return Generators.booleans().next()
                ? "%2e%252e%2f../etc/" + target
                : "%252e%2e%252f%2e%2e/etc/" + target;
    }

    private String generateTripleEncoding() {
        return Generators.booleans().next()
                ? "%25252e%25252e%25252f"
                : "%252525%252e%252525%2e%252525%2f";
    }

    private String generateCaseVariationDoubleEncoding() {
        return Generators.booleans().next()
                ? "%252E%252E%252F"
                : "%252e%252E%252f%252F";
    }

    private String generateWindowsDoubleEncoding() {
        int depth = depthGen.next();
        StringBuilder pattern = new StringBuilder();

        for (int i = 0; i < depth; i++) {
            pattern.append("%255c%252e%252e");
        }
        pattern.append("%255c");

        if (Generators.booleans().next()) {
            pattern.append(generateTargetFile());
        }

        return pattern.toString();
    }

    private String generateLegitimatePathDoubleEncoding() {
        String prefix = generatePathPrefix();
        return "/" + prefix + "%252e%252e%252f%252e%252e%252f" + generateTargetFile();
    }

    private String generateDeepDoubleEncoding() {
        int depth = depthGen.next() + 2;  // Ensure deep encoding
        StringBuilder pattern = new StringBuilder();

        for (int i = 0; i < depth; i++) {
            pattern.append("%252e%252e%252f");
        }

        return pattern.toString();
    }

    private String generatePathPrefix() {
        return switch (pathPrefixSelector.next()) {
            case 1 -> "api";
            case 2 -> "admin";
            case 3 -> "files";
            case 4 -> "config";
            case 5 -> "upload";
            case 6 -> "backup";
            default -> "api";
        };
    }

    private String generateTargetFile() {
        return switch (targetFileSelector.next()) {
            case 1 -> "passwd";
            case 2 -> "shadow";
            case 3 -> "config";
            case 4 -> "cmd.exe";
            case 5 -> "win.ini";
            case 6 -> "hosts";
            default -> "passwd";
        };
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}