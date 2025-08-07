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
package de.cuioss.tools.support;

import de.cuioss.test.generator.Generators;
import lombok.experimental.UtilityClass;

import static de.cuioss.tools.string.MoreStrings.isEmpty;

/**
 * Simple Helper that shuffle lower / uppercase for strings.
 *
 * @author Oliver Wolff
 *
 */
@UtilityClass
public class StringCaseShuffler {

    /**
     * Shuffles the case of a given string. Shuffling is done for every Character
     * that is a {@link Character#isAlphabetic(int)}
     *
     * @param toShuffle if {@code null} or empty the given String will be returned
     * @return the shuffled string
     */
    public static String shuffleCase(String toShuffle) {
        if (isEmpty(toShuffle)) {
            return toShuffle;
        }
        var result = new StringBuilder();
        for (char c : toShuffle.toCharArray()) {
            result.append(handleSingleCharacter(c));
        }
        return result.toString();
    }

    private static char handleSingleCharacter(char c) {
        if (!Character.isAlphabetic(c)) {
            return c;
        }
        if (Generators.booleans().next()) {
            return Character.toUpperCase(c);
        }
        return Character.toLowerCase(c);
    }
}
