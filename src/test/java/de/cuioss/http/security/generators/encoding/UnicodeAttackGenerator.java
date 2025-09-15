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
 * Generates Unicode-based attack patterns.
 *
 * <p>QI-6: Converted from fixedValues() to dynamic algorithmic generation.</p>
 *
 * Implements: Task G3 from HTTP verification specification
 */
public class UnicodeAttackGenerator implements TypedGenerator<String> {

    // QI-6: Dynamic generation components
    private final TypedGenerator<Integer> unicodeAttackTypeGen = Generators.integers(1, 6);
    private final TypedGenerator<Integer> pathTargetSelector = Generators.integers(1, 4);

    private final TypedGenerator<Boolean> combineGen = Generators.booleans();

    @Override
    public String next() {
        String attack = generateUnicodeAttack();

        if (combineGen.next()) {
            // Combine with path traversal
            return attack + "../" + generatePathTarget();
        }

        return attack;
    }

    private String generateUnicodeAttack() {
        return switch (unicodeAttackTypeGen.next()) {
            case 1 -> "\u002e\u002e\u002f";           // Unicode dots and slash
            case 2 -> "\u2024\u2024\u2215";           // Lookalike characters
            case 3 -> "\u202e";                       // Right-to-left override
            case 4 -> "\u200b";                       // Zero-width space
            case 5 -> "\uFEFF";                       // Zero-width no-break space
            case 6 -> "\u0000";                        // Null character
            default -> "\u002e\u002e\u002f";
        };
    }

    private String generatePathTarget() {
        return switch (pathTargetSelector.next()) {
            case 1 -> "etc/passwd";
            case 2 -> "etc/shadow";
            case 3 -> "windows/win.ini";
            case 4 -> "boot.ini";
            default -> "etc/passwd";
        };
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}