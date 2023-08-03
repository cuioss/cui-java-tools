package de.cuioss.tools.lang;

import lombok.experimental.UtilityClass;

/**
 * Overladed methods to check the emptiness of given primitive arrays. With
 * empty being defined as is the given elements are {@code null} or 0 ==
 * array.length
 *
 * @author Oliver Wolff
 *
 */
@UtilityClass
public class MoreArrays {

    /**
     * Simple check method for a {@code null} safe check of the emptiness of the
     * given parameter.
     *
     * @param array to be checked, may be null
     * @return {@code true} is the given elements are {@code null} or 0 ==
     *         array.length
     */
    public static boolean isEmpty(byte[] array) {
        return null == array || 0 == array.length;
    }

    /**
     * Simple check method for a {@code null} safe check of the emptiness of the
     * given parameter.
     *
     * @param array to be checked, may be null
     * @return {@code true} is the given elements are {@code null} or 0 ==
     *         array.length
     */
    public static boolean isEmpty(char[] array) {
        return null == array || 0 == array.length;
    }

    /**
     * Simple check method for a {@code null} safe check of the emptiness of the
     * given parameter.
     *
     * @param array to be checked, may be null
     * @return {@code true} is the given elements are {@code null} or 0 ==
     *         array.length
     */
    public static boolean isEmpty(boolean[] array) {
        return null == array || 0 == array.length;
    }

    /**
     * Simple check method for a {@code null} safe check of the emptiness of the
     * given parameter.
     *
     * @param array to be checked, may be null
     * @return {@code true} is the given elements are {@code null} or 0 ==
     *         array.length
     */
    public static boolean isEmpty(int[] array) {
        return null == array || 0 == array.length;
    }

    /**
     * Simple check method for a {@code null} safe check of the emptiness of the
     * given parameter.
     *
     * @param array to be checked, may be null
     * @return {@code true} is the given elements are {@code null} or 0 ==
     *         array.length
     */
    public static boolean isEmpty(long[] array) {
        return null == array || 0 == array.length;
    }

    /**
     * Simple check method for a {@code null} safe check of the emptiness of the
     * given parameter.
     *
     * @param array to be checked, may be null
     * @return {@code true} is the given elements are {@code null} or 0 ==
     *         array.length
     */
    public static boolean isEmpty(double[] array) {
        return null == array || 0 == array.length;
    }

    /**
     * Simple check method for a {@code null} safe check of the emptiness of the
     * given parameter.
     *
     * @param array to be checked, may be null
     * @return {@code true} is the given elements are {@code null} or 0 ==
     *         array.length
     */
    public static boolean isEmpty(float[] array) {
        return null == array || 0 == array.length;
    }

    /**
     * Simple check method for a {@code null} safe check of the emptiness of the
     * given parameter.
     *
     * @param array to be checked, may be null
     * @return {@code true} is the given elements are {@code null} or 0 ==
     *         array.length
     */
    public static boolean isEmpty(short[] array) {
        return null == array || 0 == array.length;
    }
}
