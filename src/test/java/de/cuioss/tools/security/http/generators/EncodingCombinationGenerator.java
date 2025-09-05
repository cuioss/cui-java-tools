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
 * Generates various encoding combinations for bypass attempts.
 * Implements: Task G2 from HTTP verification specification
 */
public class EncodingCombinationGenerator implements TypedGenerator<String> {

    private final TypedGenerator<String> basePatternGen = Generators.fixedValues(
            "../",
            "..\\",
            "../../",
            "../../../"
    );

    private final TypedGenerator<Integer> encodingLevelGen = Generators.integers(1, 3);
    private final TypedGenerator<Boolean> mixedCaseGen = Generators.booleans();

    @Override
    public String next() {
        String basePattern = basePatternGen.next();
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