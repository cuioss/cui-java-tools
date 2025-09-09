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
 * Generates Unicode-based attack patterns.
 * Implements: Task G3 from HTTP verification specification
 */
public class UnicodeAttackGenerator implements TypedGenerator<String> {

    private final TypedGenerator<String> unicodeAttacks = Generators.fixedValues(
            "\u002e\u002e\u002f",           // Unicode dots and slash
            "\u2024\u2024\u2215",           // Lookalike characters
            "\u202e",                       // Right-to-left override
            "\u200b",                       // Zero-width space
            "\uFEFF",                       // Zero-width no-break space
            "\u0000"                        // Null character
    );

    private final TypedGenerator<Boolean> combineGen = Generators.booleans();

    @Override
    public String next() {
        String attack = unicodeAttacks.next();

        if (combineGen.next()) {
            // Combine with path traversal
            return attack + "../etc/passwd";
        }

        return attack;
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}