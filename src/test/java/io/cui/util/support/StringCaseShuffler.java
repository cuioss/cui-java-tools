package io.cui.util.support;

import static io.cui.util.string.MoreStrings.isEmpty;

import lombok.experimental.UtilityClass;

/**
 * Simple Helper that shuffle lower / uppercase for strings.
 *
 * @author Oliver Wolff
 *
 */
@UtilityClass
public class StringCaseShuffler {

    /**
     * Shuffles the case of a given string. Shuffling is done for every Character that is a
     * {@link Character#isAlphabetic(int)}
     *
     * @param toShuffle if {@code null} or empty the given String will be returned
     * @return the shuffled string
     */
    public static final String shuffleCase(String toShuffle) {
        if (isEmpty(toShuffle)) {
            return toShuffle;
        }
        StringBuilder result = new StringBuilder();
        for (char c : toShuffle.toCharArray()) {
            result.append(handleSingleCharacter(c));
        }
        return result.toString();
    }

    private static char handleSingleCharacter(char c) {
        if (!Character.isAlphabetic(c)) {
            return c;
        }
        if (Generators.randomBoolean()) {
            return Character.toUpperCase(c);
        }
        return Character.toLowerCase(c);
    }
}