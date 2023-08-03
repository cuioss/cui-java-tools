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
