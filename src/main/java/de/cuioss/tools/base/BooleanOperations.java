/*
 * Copyright 2023 the original author or authors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.tools.base;

import lombok.experimental.UtilityClass;

/**
 * Utility Class providing some boolean operations. In essence, it simplifies
 * 'or' and 'and' operations. Some examples from the unit-tests:
 *
 * <pre>
 *
 * &#64;Test
 * void shouldDetectAnyTrue() {
 *     assertTrue(BooleanOperations.isAnyTrue(true));
 *     assertTrue(BooleanOperations.isAnyTrue(true, true));
 *     assertTrue(BooleanOperations.isAnyTrue(true, false));
 *     assertFalse(BooleanOperations.isAnyTrue(false, false));
 *     // Not really sensible, but defined contract -> Corner Case
 *     assertFalse(BooleanOperations.isAnyTrue());
 *     assertFalse(BooleanOperations.isAnyTrue(null));
 * }
 *
 * &#64;Test
 * void shouldDetectAnyFalse() {
 *     assertFalse(BooleanOperations.isAnyFalse(true));
 *     assertTrue(BooleanOperations.isAnyFalse(true, false));
 *     assertTrue(BooleanOperations.isAnyFalse(false, false));
 *     // Not really sensible, but defined contract -> Corner Case
 *     assertFalse(BooleanOperations.isAnyFalse());
 *     assertFalse(BooleanOperations.isAnyFalse(null));
 * }
 *
 * &#64;Test
 * void shouldDetectAllFalse() {
 *     assertFalse(BooleanOperations.areAllFalse(true));
 *     assertFalse(BooleanOperations.areAllFalse(true, false));
 *     assertFalse(BooleanOperations.areAllFalse(true, true));
 *     assertTrue(BooleanOperations.areAllFalse(false, false));
 *     // Not really sensible, but defined contract -> Corner Case
 *     assertFalse(BooleanOperations.areAllFalse());
 *     assertFalse(BooleanOperations.areAllFalse(null));
 * }
 *
 * &#64;Test
 * void shouldDetectAllTrue() {
 *     assertTrue(BooleanOperations.areAllTrue(true));
 *     assertFalse(BooleanOperations.areAllTrue(true, false));
 *     assertTrue(BooleanOperations.areAllTrue(true, true));
 *     assertFalse(BooleanOperations.areAllTrue(false, false));
 *     // Not really sensible, but defined contract -> Corner Case
 *     assertTrue(BooleanOperations.areAllTrue());
 *     assertTrue(BooleanOperations.areAllTrue(null));
 * }
 * </pre>
 *
 * @author Eugen Fischer
 * @author Oliver Wolff
 */
@UtilityClass
public final class BooleanOperations {

    /**
     * Efficient check for an empty boolean array, handling both null and zero-length cases.
     *
     * @param parameter the boolean array to check
     * @return true if the array is null or empty, false otherwise
     */
    private static boolean isEmpty(final boolean... parameter) {
        return parameter == null || parameter.length == 0;
    }

    /**
     * Helper method to check if array contains at least one true value.
     *
     * @param parameter array to check
     * @return true if array contains at least one true value, false otherwise
     */
    private static boolean containsTrue(final boolean... parameter) {
        if (isEmpty(parameter)) {
            return false;
        }
        for (boolean element : parameter) {
            if (element) {
                return true;
            }
        }
        return false;
    }

    /**
     * Helper method to check if an array contains at least one false value.
     *
     * @param parameter array to check
     * @return true if an array contains at least one false value, false otherwise
     */
    private static boolean containsFalse(final boolean... parameter) {
        if (isEmpty(parameter)) {
            return false;
        }
        for (boolean element : parameter) {
            if (!element) {
                return true;
            }
        }
        return false;
    }

    /**
     * Shorthand for checking if at least one of the given booleans is {@code true}
     *
     * @param parameter ellipsis of boolean values
     * @return {@code true} if one of parameters is {@code true}, {@code false}
     * otherwise.
     * If no parameter is given or parameter is null, returns {@code false}.
     */
    public static boolean isAnyTrue(final boolean... parameter) {
        return containsTrue(parameter);
    }

    /**
     * Shorthand for checking if at least one of the given booleans is {@code false}
     *
     * @param parameter ellipsis of boolean values
     * @return {@code true} if one of parameters is {@code false}, {@code false}
     * otherwise. If no parameter is given or parameter is null, returns {@code false}.
     */
    public static boolean isAnyFalse(final boolean... parameter) {
        return containsFalse(parameter);
    }

    /**
     * Shorthand for checking if all the given booleans are {@code true}
     *
     * @param parameter ellipsis of boolean values
     * @return {@code true} if all parameters are {@code true} or if no parameter is
     * given (including null case). Returns {@code false} if any parameter is {@code false}.
     */
    public static boolean areAllTrue(final boolean... parameter) {
        if (isEmpty(parameter)) {
            return true;
        }
        return !containsFalse(parameter);
    }

    /**
     * Shorthand for checking if all given booleans are {@code false}
     *
     * @param parameter ellipsis of boolean values
     * @return {@code true} if all parameters are {@code false}, {@code false}
     * otherwise. If no parameter is given or parameter is null, returns {@code false}.
     */
    public static boolean areAllFalse(final boolean... parameter) {
        if (isEmpty(parameter)) {
            return false;
        }
        return !containsTrue(parameter);
    }

    /**
     * Checks if a string represents a valid boolean value according to Java's boolean
     * parsing rules. This method is case-insensitive and considers only "true" and
     * "false" as valid boolean strings.
     * 
     * <h3>Examples:</h3>
     * <pre>
     * isValidBoolean("true")  -> true
     * isValidBoolean("TRUE")  -> true
     * isValidBoolean("false") -> true
     * isValidBoolean("False") -> true
     * isValidBoolean("yes")   -> false
     * isValidBoolean("1")     -> false
     * isValidBoolean(null)    -> false
     * isValidBoolean("")      -> false
     * </pre>
     * 
     * @param value the string to be checked, may be null
     * @return {@code true} if the given value represents a valid boolean string
     *         ("true" or "false", case-insensitive), {@code false} otherwise
     *         including null and empty strings
     * @since 2.1
     */
    public static boolean isValidBoolean(final String value) {
        if (null == value || value.isEmpty()) {
            return false;
        }
        final var lowerCase = value.toLowerCase();
        return "true".equals(lowerCase) || "false".equals(lowerCase);
    }
}
