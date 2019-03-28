/**
 * Copyright 2018, InterComponentWare AG
 *
 * NO WARRANTIES OR ANY FURTHER CONDITIONS are implied as to the availability
 * of this source code.
 *
 * In case you receive a copy of this source code you are not permitted
 * to modify, use, or distribute this copy without agreement and an explicit
 * license issued by InterComponentWare AG.
 */
/**
 *
 */
package de.icw.util.primitives;

import static com.google.common.base.Strings.isNullOrEmpty;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.google.common.base.Joiner;

import lombok.experimental.UtilityClass;

/**
 * Simple tooling for MoreStrings
 *
 * @author Oliver Wolff
 *
 */
@UtilityClass
public final class MoreStrings {

    /**
     * "Unquotes" a String, saying if the given String starts and ends with the token "'" or """ the
     * quotes will be stripped
     *
     * @param original may be null or empty
     * @return the unquoted String or the original in none could be found
     */
    public static String unquote(String original) {
        if (isNullOrEmpty(original)) {
            return original;
        }
        if (original.startsWith("\"") && original.endsWith("\"")
                || original.startsWith("'") && original.endsWith("'")) {
            return original.substring(1, original.length() - 1);
        }
        return original;
    }

    /**
     * Wrapper to {@link Joiner} simplifying the handling of empty strings that implicitly trims all
     * (empty) MoreStrings given. Use it with care
     *
     * @param separator
     * @param strings
     * @return the joined String, separated with given separator
     */
    public static String joinNotBlankStrings(String separator, List<String> strings) {
        List<String> cleanedList = new ArrayList<>();
        for (String string : strings) {
            if (!isNullOrEmpty(string) && string.trim().length() > 0) {
                cleanedList.add(string);
            }
        }

        return Joiner.on(separator).join(cleanedList);
    }

    /**
     * Wrapper to {@link Joiner} simplifying the handling of empty strings that implicitly trims all
     * (empty) MoreStrings given. Use it with care
     *
     * @param separator
     * @param strings
     * @return the joined String, separated with given separator
     */
    public static String joinNotBlankStrings(String separator, String... strings) {
        return joinNotBlankStrings(separator, Arrays.asList(strings));
    }

}
