package io.cui.util.base;

import lombok.experimental.UtilityClass;

/**
 * Utility Class providing some boolean operations. In essence it simplifies 'or' and 'and'
 * operations.
 * Some examples from the unit-tests:
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
 *
 *
 * @author Eugen Fischer
 * @author Oliver Wolff
 */
@UtilityClass
public final class BooleanOperations {

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

    private static boolean isEmpty(boolean[] parameter) {
        return null == parameter || 0 == parameter.length;
    }

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
     * @return {@code true} if one of parameters is {@code true}, {@code false} otherwise
     */
    public static boolean isAnyTrue(final boolean... parameter) {
        return containsTrue(parameter);
    }

    /**
     * Shorthand for checking if all of the given booleans are {@code true}
     *
     * @param parameter ellipsis of boolean values
     * @return {@code true} if all of parameters are {@code true} or no parameter is given ratio: no
     *         given false, {@code false} otherwise
     */
    public static boolean areAllTrue(final boolean... parameter) {
        if (isEmpty(parameter)) {
            return true;
        }
        return !containsFalse(parameter);
    }

    /**
     * Shorthand for checking if all of the given booleans are {@code false}
     *
     * @param parameter ellipsis of boolean values
     * @return {@code true} if all of parameters are {@code false}, {@code true} otherwise.
     *         {@code false} if no parameter is passed, ratio: no given false
     */
    public static boolean areAllFalse(final boolean... parameter) {
        if (isEmpty(parameter)) {
            return false;
        }
        return !containsTrue(parameter);
    }

    /**
     * Shorthand for checking if at least one of the given booleans is {@code false}
     *
     * @param parameter ellipsis of boolean values
     * @return {@code true} if one of parameters is {@code false}, {@code true} otherwise
     */
    public static boolean isAnyFalse(final boolean... parameter) {
        return containsFalse(parameter);
    }

    /**
     * @param value to be checked
     * @return true, if the given value represents a boolean value i.e. "true" or "false" ignoring case.
     */
    public static boolean isValidBoolean(String value) {
        return (Boolean.TRUE.toString().equalsIgnoreCase(value)
            || Boolean.FALSE.toString().equalsIgnoreCase(value));
    }
}
