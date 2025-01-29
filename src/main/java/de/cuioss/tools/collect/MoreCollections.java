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
package de.cuioss.tools.collect;

import static de.cuioss.tools.base.Preconditions.checkArgument;
import static java.util.Objects.isNull;

import lombok.experimental.UtilityClass;

import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * <h2>Overview</h2> Utility Methods for Collections and some types to be used
 * in the context of Collections.
 *
 * <h3>isEmpty()</h3> The overloaded method
 * {@link MoreCollections#isEmpty(Collection)} checks all kinds of Collections /
 * varargs parameter for not being null and emptiness. In case of
 * {@link Stream}s it solely checks for being not null in order not to consume
 * it.
 *
 * <h3>requireNotEmpty()</h3> The overloaded method
 * {@link MoreCollections#requireNotEmpty(Collection)} checks all kinds of
 * Collections / varargs parameter for not being null nor empty. In case of
 * being null / empty they will throw an {@link IllegalArgumentException}
 *
 * <h3>Map Difference</h3> The method
 * {@link MoreCollections#difference(Map, Map)} creates an {@link MapDifference}
 * view on the two given maps to check, well whether they are equal or
 * not and if not which elements are differing.
 *
 * <h3>Map contains key</h3> Check whether the given Map contains at least one
 * of the given keys (varags)
 *
 * @author Oliver Wolff
 */
@UtilityClass
public final class MoreCollections {

    /**
     * Simple check method for a {@code null} safe check of the emptiness of the
     * given varags-parameter.
     *
     * @param elements to be checked may be null
     * @return {@code true} is the given elements are {@code null} or {@code empty}
     */
    public static boolean isEmpty(Object... elements) {
        return isNull(elements) || elements.length == 0;
    }

    /**
     * Simple check method for a {@code null} safe check of the emptiness of the
     * given parameter.
     *
     * @param elements to be checked, may be null
     * @return {@code true} is the given elements are {@code null} or {@code empty}
     */
    public static boolean isEmpty(Iterable<?> elements) {
        return Optional.ofNullable(elements)
                .map(it -> !it.iterator().hasNext())
                .orElse(true);
    }

    /**
     * Simple check method for a {@code null} safe check of the emptiness of the
     * given parameter.
     *
     * @param elements to be checked, may be null
     * @return {@code true} is the given elements are {@code null} or {@code empty}
     */
    public static boolean isEmpty(Collection<?> elements) {
        return Optional.ofNullable(elements)
                .map(Collection::isEmpty)
                .orElse(true);
    }

    /**
     * Simple check method for a {@code null} safe check of the emptiness of the
     * given parameter.
     *
     * @param map to be checked, may be null
     * @return {@code true} is the given elements are {@code null} or {@code empty}
     */
    public static boolean isEmpty(Map<?, ?> map) {
        return Optional.ofNullable(map)
                .map(Map::isEmpty)
                .orElse(true);
    }

    /**
     * Simple check method for a {@code null} safe check of the emptiness of the
     * given parameter.
     *
     * @param elements to be checked, may be null
     * @return {@code true} is the given elements are {@code null} or {@code empty}
     */
    public static boolean isEmpty(Iterator<?> elements) {
        return Optional.ofNullable(elements)
                .map(it -> !it.hasNext())
                .orElse(true);
    }

    /**
     * Shorthand for checking whether the given elements are empty or not.
     *
     * @param <T>      identifying the type to be checked
     * @param elements to be checked
     * @return the given parameter
     * @throws IllegalArgumentException in case the given elements are {@code null}
     *                                  or empty
     */
    @SafeVarargs
    public static <T> T[] requireNotEmpty(T... elements) {
        checkArgument(!isEmpty(elements));
        return elements;
    }

    /**
     * Shorthand for checking whether the given elements are empty or not.
     *
     * @param <T>      identifying the type to be checked
     * @param elements to be checked
     * @return the given parameter
     * @throws IllegalArgumentException in case the given elements are {@code null}
     *                                  or empty
     */
    public static <T> Collection<T> requireNotEmpty(Collection<T> elements) {
        checkArgument(!isEmpty(elements));
        return elements;
    }

    /**
     * Shorthand for checking whether the given elements are empty or not.
     *
     * @param <T>      identifying the type to be checked
     * @param elements to be checked
     * @param message  to be set in error-case
     * @return the given parameter
     * @throws IllegalArgumentException in case the given elements are {@code null}
     *                                  or empty
     */
    public static <T> Collection<T> requireNotEmpty(Collection<T> elements, String message) {
        checkArgument(!isEmpty(elements), message);
        return elements;
    }

    /**
     * Shorthand for checking whether the given elements are empty or not.
     *
     * @param <K>      the type for the key
     * @param <V>      the type for the value
     * @param elements to be checked
     * @return the given parameter
     * @throws IllegalArgumentException in case the given elements are {@code null}
     *                                  or empty
     */
    public static <K, V> Map<K, V> requireNotEmpty(Map<K, V> elements) {
        checkArgument(!isEmpty(elements));
        return elements;
    }

    /**
     * Shorthand for checking whether the given elements are empty or not.
     *
     * @param <K>      the type for the key
     * @param <V>      the type for the value
     * @param elements to be checked
     * @param message  to be set in error-case
     * @return the given parameter
     * @throws IllegalArgumentException in case the given elements are {@code null}
     *                                  or empty
     */
    public static <K, V> Map<K, V> requireNotEmpty(Map<K, V> elements, String message) {
        checkArgument(!isEmpty(elements), message);
        return elements;
    }

    /**
     * Shorthand for checking whether the given elements are empty or not.
     *
     * @param <T>      identifying the type to be checked
     * @param elements to be checked
     * @return the given parameter
     * @throws IllegalArgumentException in case the given elements are {@code null}
     *                                  or empty
     */
    public static <T> Iterable<T> requireNotEmpty(Iterable<T> elements) {
        checkArgument(!isEmpty(elements));
        return elements;
    }

    /**
     * Shorthand for checking whether the given elements are empty or not.
     *
     * @param <T>      identifying the type to be checked
     * @param elements to be checked
     * @param message  to be set in error-case
     * @return the given parameter
     * @throws IllegalArgumentException in case the given elements are {@code null}
     *                                  or empty
     */
    public static <T> Iterable<T> requireNotEmpty(Iterable<T> elements, String message) {
        checkArgument(!isEmpty(elements), message);
        return elements;
    }

    /**
     * Shorthand for checking whether the given elements are empty or not.
     *
     * @param elements to be checked
     * @return the given parameter
     * @throws IllegalArgumentException in case the given elements are {@code null}
     *                                  or empty
     */
    public static <T> Iterator<T> requireNotEmpty(Iterator<T> elements) {
        checkArgument(!isEmpty(elements));
        return elements;
    }

    /**
     * Shorthand for checking whether the given elements are empty or not.
     *
     * @param <T>      identifying the type to be checked
     * @param elements to be checked
     * @param message  to be set in error-case
     * @return the given parameter
     * @throws IllegalArgumentException in case the given elements are {@code null}
     *                                  or empty
     */
    public static <T> Iterator<T> requireNotEmpty(Iterator<T> elements, String message) {
        checkArgument(!isEmpty(elements), message);
        return elements;
    }

    /**
     * Shorthand for checking whether the given elements are empty or not.
     * <em>Caution: </em> In order not to consume the stream only a null check will
     * be performed.
     *
     * @param <T>      identifying the type to be checked
     * @param elements to be checked
     * @return the given parameter
     * @throws IllegalArgumentException in case the given elements are {@code null}
     */
    public static <T> Stream<T> requireNotEmpty(Stream<T> elements) {
        checkArgument(!isEmpty(elements));
        return elements;
    }

    /**
     * Shorthand for checking whether the given elements are empty or not.
     * <em>Caution: </em> In order not to consume the stream only a null check will
     * be performed.
     *
     * @param <T>      identifying the type to be checked
     * @param elements to be checked
     * @param message  to be set in error-case
     * @return the given parameter
     * @throws IllegalArgumentException in case the given elements are {@code null}
     */
    public static <T> Stream<T> requireNotEmpty(Stream<T> elements, String message) {
        checkArgument(!isEmpty(elements), message);
        return elements;
    }

    /**
     * Simple check method for a {@code null} safe check of the emptiness of the
     * given parameter. <em>Caution: </em> In order not to consume the stream only a
     * null check will be performed.
     *
     * @param elements to be checked, may be null
     * @return {@code true} is the given elements are {@code null}. The Stream
     * content will be untouched
     */
    public static boolean isEmpty(Stream<?> elements) {
        return isNull(elements);
    }

    /**
     * Checks whether the given map contains at least one of the given keys to be
     * checked.
     *
     * @param map  to be checked. If it is {@code null} or empty the method will
     *             always return {@code false}
     * @param keys to be checked. If it is {@code null} or empty the method will
     *             always return {@code false}
     * @return {@code true} if the map contains at lest one of the given keys,
     * {@code false} otherwise
     */
    public static boolean containsKey(Map<?, ?> map, Object... keys) {
        if (isEmpty(map) || isEmpty(keys)) {
            return false;
        }
        for (Object key : keys) {
            if (map.containsKey(key)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Computes the difference between two maps. The returned difference will include
     * entries that are present only in the left map, entries that are present only in
     * the right map, and entries that have different values in both maps.
     *
     * @param <K>   the type of map keys
     * @param <V>   the type of map values
     * @param left  first map
     * @param right second map
     * @return the difference between the maps
     * @see <a href="https://github.com/google/guava/blob/master/guava/src/com/google/common/collect/Maps.java#L504"></a>
     */
    @SuppressWarnings("avaarchitecture:S7027") // owolff: No issue, because it delegates to MapDiffenceImpl
    public static <K, V> MapDifference<K, V> difference(Map<? extends K, ? extends V> left,
            Map<? extends K, ? extends V> right) {
        return MapDiffenceImpl.from(left, right);
    }

}
