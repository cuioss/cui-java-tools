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
 * Generates various encoding combinations for bypass attempts.
 *
 * <p>QI-6: Converted from fixedValues() to dynamic algorithmic generation.</p>
 *
 * Implements: Task G2 from HTTP verification specification
 */
public class EncodingCombinationGenerator implements TypedGenerator<String> {

    // QI-6: Dynamic generation components
    private final TypedGenerator<Integer> basePatternTypeGen = Generators.integers(1, 5);
    private final TypedGenerator<Integer> depthGen = Generators.integers(1, 4);
    private final TypedGenerator<Boolean> useBackslashGen = Generators.booleans();

    private final TypedGenerator<Integer> encodingLevelGen = Generators.integers(1, 3);
    private final TypedGenerator<Boolean> mixedCaseGen = Generators.booleans();

    @Override
    public String next() {
        String basePattern = generateBasePattern();
        int level = encodingLevelGen.next();
        boolean mixedCase = mixedCaseGen.next();

        String encoded = basePattern;

        // Apply encoding levels
        for (int i = 0; i < level; i++) {
            encoded = urlEncode(encoded);
        }

        // Apply mixed case if selected
        if (mixedCase) {
            encoded = applyMixedCase(encoded);
        }

        return encoded;
    }

    private String generateBasePattern() {
        return switch (basePatternTypeGen.next()) {
            case 1 -> generateSimpleTraversal();
            case 2 -> generateWindowsTraversal();
            case 3 -> generateDeepTraversal();
            case 4 -> generateMixedSeparatorTraversal();
            case 5 -> generateCustomDepthTraversal();
            default -> generateSimpleTraversal();
        };
    }

    private String generateSimpleTraversal() {
        return useBackslashGen.next() ? "..\\" : "../";
    }

    private String generateWindowsTraversal() {
        return "..\\";
    }

    private String generateDeepTraversal() {
        int depth = depthGen.next();
        String separator = useBackslashGen.next() ? "\\" : "/";
        StringBuilder pattern = new StringBuilder();

        for (int i = 0; i < depth; i++) {
            pattern.append("..").append(separator);
        }

        return pattern.toString();
    }

    private String generateMixedSeparatorTraversal() {
        // Mix forward and backward slashes
        return "../..\\../";
    }

    private String generateCustomDepthTraversal() {
        int customDepth = Generators.integers(2, 6).next();
        String separator = useBackslashGen.next() ? "\\" : "/";
        StringBuilder pattern = new StringBuilder();

        for (int i = 0; i < customDepth; i++) {
            pattern.append("..").append(separator);
        }

        return pattern.toString();
    }

    private String urlEncode(String input) {
        // URL encode with %25 for % in multi-level
        return input.replace(".", "%2e")
                .replace("/", "%2f")
                .replace("%", "%25");
    }

    private String applyMixedCase(String input) {
        // Mix uppercase and lowercase in hex encoding
        return input.replaceAll("%2e", "%2E")
                .replaceAll("%2f", "%2F");
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}