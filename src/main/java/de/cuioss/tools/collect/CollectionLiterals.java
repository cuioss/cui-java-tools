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
package de.cuioss.tools.collect;

import lombok.experimental.UtilityClass;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.stream.Stream;

import static de.cuioss.tools.collect.MoreCollections.isEmpty;

/**
 * <h2>Overview</h2> Provides a number of methods simplifying the task of
 * creating populated {@link java.util.Collection}s. In essence its doing the
 * same compared to the corresponding com.google.common.collect types but with
 * different semantics (like naming, types) and is designed as a one-stop
 * utility class. It differentiates between the subtypes and mutability /
 * immutability. This class is complementary to the corresponding guava types.
 * <h3>Lists</h3>
 *
 * <pre>
 *  assertMutable(CollectionLiterals#mutableList("1"));
 *  assertMutable(CollectionLiterals#mutableList("1", "2"));
 *  assertMutable(CollectionLiterals#mutableList(Arrays.asList("1", "2").stream()));
 * </pre>
 *
 * <pre>
 *  assertImmutable(CollectionLiterals#immutableList("1"));
 *  assertImmutable(CollectionLiterals#immutableList("1", "2"));
 *  assertImmutable(CollectionLiterals#immutableList(Arrays.asList("1", "2").stream()));
 * </pre>
 *
 * <h3>Sets</h3>
 *
 * <pre>
 *  assertMutable(CollectionLiterals#mutableSet("1"));
 *  assertMutable(CollectionLiterals#mutableSet("1", "2"));
 *  assertMutable(CollectionLiterals#mutableSet(Arrays.asList("1", "2").stream()));
 * </pre>
 *
 * <pre>
 *  assertImmutable(CollectionLiterals#immutableSet("1"));
 *  assertImmutable(CollectionLiterals#immutableSet("1", "2"));
 *  assertImmutable(CollectionLiterals#immutableSet(Arrays.asList("1", "2").stream()));
 * </pre>
 *
 * <h3>Maps</h3>
 *
 * <pre>
 * assertMutable(CollectionLiterals#mutableMap());
 * assertMutable(CollectionLiterals#mutableMap("1", "1-1"));
 * assertMutable(CollectionLiterals#mutableMap("1", "1-1", "2", "2-2", "3", "3-3", "4", "4-4"));
 * </pre>
 *
 * <pre>
 * assertImmutable(CollectionLiterals#immutableMap());
 * assertImmutable(CollectionLiterals#immutableMap("1", "1-1"));
 * assertImmutable(CollectionLiterals#immutableMap("1", "1-1", "2", "2-2", "3", "3-3", "4", "4-4"));
 * </pre>
 *
 * @author Oliver Wolff
 */
@SuppressWarnings("javaarchitecture:S7027")
// Intended circular dependency within collection utilities
@UtilityClass
public class CollectionLiterals {

    /**
     * <p>
     * mutableList.
     * </p>
     *
     * @return a newly created empty {@link java.util.ArrayList}
     * @param <E> a E class
     */
    public static <E> List<E> mutableList() {
        return new ArrayList<>();
    }

    /**
     * Creates a <i>mutable</i> {@code List} instance containing the given elements.
     *
     * @param elements to be added
     * @return the <i>mutable</i> {@link java.util.List} with the given elements
     * @param <E> a E class
     */
    @SafeVarargs
    public static <E> List<E> mutableList(E... elements) {
        if (isEmpty(elements)) {
            return new ArrayList<>();
        }
        return new ArrayList<>(Arrays.asList(elements));
    }

    /**
     * Creates a <i>mutable</i> {@code List} instance containing the given element
     *
     * @param element to be added
     * @return the <i>mutable</i> {@link java.util.List} with the given element
     * @param <E> a E class
     */
    public static <E> List<E> mutableList(E element) {
        List<E> list = new ArrayList<>();
        list.add(element);
        return list;
    }

    /**
     * Creates a <i>mutable</i> {@code List} instance containing the given elements.
     *
     * @param elements to be added. If it is null and empty <i>mutable</i> list will
     *                 be returned
     * @return the <i>mutable</i> {@link java.util.List} with the given elements
     * @param <E> a E class
     */
    public static <E> List<E> mutableList(Iterable<? extends E> elements) {
        var list = new ArrayList<E>();
        if (isEmpty(elements)) {
            return list;
        }
        elements.forEach(list::add);
        return list;
    }

    /**
     * Creates a <i>mutable</i> {@code List} instance containing the given elements.
     *
     * @param elements to be added. If it is null and empty <i>mutable</i> list will
     *                 be returned
     * @return the <i>mutable</i> {@link java.util.List} with the given elements
     * @param <E> a E class
     */
    public static <E> List<E> mutableList(Collection<? extends E> elements) {
        if (isEmpty(elements)) {
            return new ArrayList<>();
        }
        return new ArrayList<>(elements);
    }

    /**
     * Creates a <i>mutable</i> {@code List} instance containing the given elements.
     * <em>Caution:</em> The stream will be consumed by this operation
     *
     * @param elements to be added. If it is null an empty <i>mutable</i>
     *                 {@code List} will be returned
     * @return the <i>mutable</i> {@code List} with the given elements
     * @param <E> a E class
     */
    public static <E> List<E> mutableList(Stream<? extends E> elements) {
        List<E> list = new ArrayList<>();
        if (isEmpty(elements)) {
            return list;
        }
        elements.forEach(list::add);
        return list;
    }

    /**
     * Creates a <i>mutable</i> {@code List} instance containing the given elements.
     *
     * @param elements to be added. If it is null and empty <i>mutable</i> list will
     *                 be returned
     * @return the <i>mutable</i> {@link java.util.List} with the given elements
     * @param <E> a E class
     */
    public static <E> List<E> mutableList(Iterator<? extends E> elements) {
        List<E> list = new ArrayList<>();
        if (isEmpty(elements)) {
            return list;
        }
        while (elements.hasNext()) {
            list.add(elements.next());
        }
        return list;
    }

    /**
     * Creates an <i>immutable</i> {@code List} instance. Convenience method for
     * {@link java.util.Collections#emptyList()}
     *
     * @return the <i>immutable</i> {@link java.util.List} without any element
     * @param <E> a E class
     */
    public static <E> List<E> immutableList() {
        return Collections.emptyList();
    }

    /**
     * Creates an <i>immutable</i> {@code List} instance containing the given
     * elements.
     *
     * @param elements to be wrapped, must not be null
     * @return the <i>immutable</i> {@link java.util.List} with the given elements
     * @param <E> a E class
     */
    @SafeVarargs
    public static <E> List<E> immutableList(E... elements) {
        if (isEmpty(elements)) {
            return Collections.emptyList();
        }
        return Collections.unmodifiableList(mutableList(elements));
    }

    /**
     * Creates an <i>immutable</i> {@code List} instance containing the given
     * element.
     *
     * @param element to be wrapped, must not be null
     * @return the <i>immutable</i> {@link java.util.List} with the given elements
     * @param <E> a E class
     */
    public static <E> List<E> immutableList(E element) {
        if (null == element) {
            return Collections.emptyList();
        }
        return List.of(element);
    }

    /**
     * Creates an <i>immutable</i> {@code List} instance containing the given
     * elements.
     *
     * @param elements to be wrapped, must not be null
     * @return the <i>immutable</i> {@link java.util.List} with the given elements
     * @param <E> a E class
     */
    public static <E> List<E> immutableList(Iterable<? extends E> elements) {
        if (isEmpty(elements)) {
            return Collections.emptyList();
        }
        return Collections.unmodifiableList(mutableList(elements));
    }

    /**
     * Creates an <i>immutable</i> {@code List} instance containing the given
     * elements.
     *
     * @param elements to be wrapped, must not be null
     * @return the <i>immutable</i> {@link java.util.List} with the given elements.
     *         It implicitly creates a copy
     * @param <E> a E class
     */
    public static <E> List<E> immutableList(Collection<? extends E> elements) {
        if (isEmpty(elements)) {
            return Collections.emptyList();
        }

        return Collections.unmodifiableList(mutableList(elements));
    }

    /**
     * Creates an <i>immutable</i> {@code List} instance containing the given
     * elements. <em>Caution:</em> The stream will be consumed by this operation
     *
     * @param elements to be wrapped, must not be null
     * @return the <i>immutable</i> {@link java.util.List} with the given elements
     * @param <E> a E class
     */
    public static <E> List<E> immutableList(Stream<? extends E> elements) {
        if (isEmpty(elements)) {
            return Collections.emptyList();
        }
        return Collections.unmodifiableList(mutableList(elements));
    }

    /**
     * Creates an <i>immutable</i> {@code List} instance containing the given
     * elements.
     *
     * @param elements to be wrapped, must not be null
     * @return the <i>immutable</i> {@link java.util.List} with the given elements
     * @param <E> a E class
     */
    public static <E> List<E> immutableList(Iterator<? extends E> elements) {
        if (isEmpty(elements)) {
            return Collections.emptyList();
        }
        return Collections.unmodifiableList(mutableList(elements));
    }

    /**
     * <p>
     * mutableSet.
     * </p>
     *
     * @return a newly created empty {@link java.util.HashSet}
     * @param <E> a E class
     */
    public static <E> Set<E> mutableSet() {
        return new HashSet<>();
    }

    /**
     * <p>
     * mutableSet.
     * </p>
     *
     * @param element to be added. If it is {@code null} it will not be added
     * @return a newly created empty {@link java.util.HashSet} with the given
     *         elements
     * @param <E> a E class
     */
    public static <E> Set<E> mutableSet(E element) {
        Set<E> set = new HashSet<>();
        if (null == element) {
            return set;
        }
        set.add(element);
        return set;
    }

    /**
     * <p>
     * mutableSet.
     * </p>
     *
     * @param elements to be added
     * @return a newly created empty {@link java.util.HashSet} with the given
     *         elements
     * @param <E> a E class
     */
    @SafeVarargs
    public static <E> Set<E> mutableSet(E... elements) {
        if (isEmpty(elements)) {
            return new HashSet<>();
        }
        return new HashSet<>(Arrays.asList(elements));
    }

    /**
     * Creates a <i>mutable</i> {@code Set} instance containing the given elements.
     *
     * @param elements to be added. If it is null and empty <i>mutable</i> list will
     *                 be returned
     * @return the <i>mutable</i> {@link java.util.Set} with the given elements
     * @param <E> a E class
     */
    public static <E> Set<E> mutableSet(Iterable<? extends E> elements) {
        Set<E> set = new HashSet<>();
        if (isEmpty(elements)) {
            return set;
        }
        elements.forEach(set::add);
        return set;

    }

    /**
     * Creates a <i>mutable</i> {@code Set} instance containing the given elements.
     *
     * @param elements to be added. If it is null and empty <i>mutable</i> list will
     *                 be returned
     * @return the <i>mutable</i> {@link java.util.Set} with the given elements
     * @param <E> a E class
     */
    public static <E> Set<E> mutableSet(Collection<? extends E> elements) {
        if (isEmpty(elements)) {
            return new HashSet<>();
        }
        return new HashSet<>(elements);
    }

    /**
     * Creates a <i>mutable</i> {@code Set} instance containing the given elements.
     *
     * @param elements to be added. If it is null and empty <i>mutable</i> list will
     *                 be returned
     * @return the <i>mutable</i> {@link java.util.Set} with the given elements
     * @param <E> a E class
     */
    public static <E> Set<E> mutableSet(Iterator<? extends E> elements) {
        Set<E> set = new HashSet<>();
        if (isEmpty(elements)) {
            return set;
        }
        while (elements.hasNext()) {
            set.add(elements.next());
        }
        return set;
    }

    /**
     * Creates a <i>mutable</i> {@code Set} instance containing the given elements.
     * <em>Caution:</em> The stream will be consumed by this operation
     *
     * @param elements to be added. If it is null and empty <i>mutable</i>
     *                 {@link java.util.Set} will be returned
     * @return the <i>mutable</i> {@link java.util.Set} with the given elements
     * @param <E> a E class
     */
    public static <E> Set<E> mutableSet(Stream<? extends E> elements) {
        Set<E> set = new HashSet<>();
        if (isEmpty(elements)) {
            return set;
        }
        elements.forEach(set::add);
        return set;
    }

    /**
     * <p>
     * immutableSet.
     * </p>
     *
     * @return a newly created empty {@link java.util.HashSet} Convenience method
     *         for {@link java.util.Collections#emptySet()}
     * @param <E> a E class
     */
    public static <E> Set<E> immutableSet() {
        return Collections.emptySet();
    }

    /**
     * Creates an <i>immutable</i> {@code Set} instance containing the given
     * elements.
     *
     * @param element to be wrapped, must not be null
     * @return the <i>immutable</i> {@link java.util.Set} with the given elements
     * @param <E> a E class
     */
    public static <E> Set<E> immutableSet(E element) {
        if (null == element) {
            return Collections.emptySet();
        }
        return Set.of(element);
    }

    /**
     * Creates an <i>immutable</i> {@code Set} instance containing the given
     * elements.
     *
     * @param elements to be wrapped, must not be null
     * @return the <i>immutable</i> {@link java.util.Set} with the given elements
     * @param <E> a E class
     */
    @SafeVarargs
    public static <E> Set<E> immutableSet(E... elements) {
        if (isEmpty(elements)) {
            return Collections.emptySet();
        }
        return Collections.unmodifiableSet(mutableSet(elements));
    }

    /**
     * Creates an <i>immutable</i> {@code Set} instance containing the given
     * elements.
     *
     * @param elements to be wrapped
     * @return the <i>immutable</i> {@link java.util.Set} with the given elements
     * @param <E> a E class
     */
    public static <E> Set<E> immutableSet(Iterable<? extends E> elements) {
        if (isEmpty(elements)) {
            return Collections.emptySet();
        }
        return Collections.unmodifiableSet(mutableSet(elements));
    }

    /**
     * Creates an <i>immutable</i> {@code Set} instance containing the given
     * elements.
     *
     * @param elements to be wrapped, must not be null
     * @return the <i>immutable</i> {@link java.util.Set} with the given elements
     * @param <E> a E class
     */
    public static <E> Set<E> immutableSet(Iterator<? extends E> elements) {
        if (isEmpty(elements)) {
            return Collections.emptySet();
        }
        return Collections.unmodifiableSet(mutableSet(elements));
    }

    /**
     * Creates an <i>immutable</i> {@code Set} instance containing the given
     * elements. <em>Caution:</em> The stream will be consumed by this operation
     *
     * @param elements to be wrapped, must not be null
     * @return the <i>immutable</i> {@link java.util.Set} with the given elements
     * @param <E> a E class
     */
    public static <E> Set<E> immutableSet(Stream<? extends E> elements) {
        if (isEmpty(elements)) {
            return Collections.emptySet();
        }
        return Collections.unmodifiableSet(mutableSet(elements));
    }

    /**
     * <p>
     * mutableSortedSet.
     * </p>
     *
     * @return a newly created empty {@link java.util.TreeSet}
     * @param <E> a E class
     */
    public static <E> SortedSet<E> mutableSortedSet() {
        return new TreeSet<>();
    }

    /**
     * <p>
     * mutableSortedSet.
     * </p>
     *
     * @param element to be added. If it is {@code null} an empty
     *                {@link java.util.SortedSet} will be returned
     * @return a newly created empty {@link java.util.TreeSet} with the given
     *         element
     * @param <E> a E class
     */
    public static <E> SortedSet<E> mutableSortedSet(E element) {
        SortedSet<E> set = new TreeSet<>();
        if (null == element) {
            return set;
        }
        set.add(element);
        return set;
    }

    /**
     * <p>
     * mutableSortedSet.
     * </p>
     *
     * @param elements to be added
     * @return a newly created empty {@link java.util.TreeSet} with the given
     *         elements
     * @param <E> a E class
     */
    @SafeVarargs
    public static <E> SortedSet<E> mutableSortedSet(E... elements) {
        SortedSet<E> set = new TreeSet<>();
        if (isEmpty(elements)) {
            return set;
        }
        set.addAll(Arrays.asList(elements));
        return set;
    }

    /**
     * Creates a <i>mutable</i> {@code SortedSet} instance containing the given
     * elements.
     *
     * @param elements to be added. If it is null and empty <i>mutable</i> list will
     *                 be returned
     * @return the <i>mutable</i> {@link java.util.TreeSet} with the given elements
     * @param <E> a E class
     */
    public static <E> SortedSet<E> mutableSortedSet(Iterable<? extends E> elements) {
        SortedSet<E> set = new TreeSet<>();
        if (null == elements) {
            return set;
        }
        elements.forEach(set::add);
        return set;
    }

    /**
     * Creates a <i>mutable</i> {@code SortedSet} instance containing the given
     * elements.
     *
     * @param elements to be added. If it is null and empty <i>mutable</i> list will
     *                 be returned
     * @return the <i>mutable</i> {@link java.util.Set} with the given elements
     * @param <E> a E class
     */
    public static <E> SortedSet<E> mutableSortedSet(Iterator<? extends E> elements) {
        SortedSet<E> set = new TreeSet<>();
        if (null == elements) {
            return set;
        }
        while (elements.hasNext()) {
            set.add(elements.next());
        }
        return set;
    }

    /**
     * Creates a <i>mutable</i> {@code SortedSet} instance containing the given
     * elements. <em>Caution:</em> The stream will be consumed by this operation
     *
     * @param elements to be added. If it is null and empty <i>mutable</i> list will
     *                 be returned
     * @return the <i>mutable</i> {@link java.util.Set} with the given elements
     * @param <E> a E class
     */
    public static <E> SortedSet<E> mutableSortedSet(Stream<? extends E> elements) {
        SortedSet<E> set = new TreeSet<>();
        if (null == elements) {
            return set;
        }
        elements.forEach(set::add);
        return set;
    }

    /**
     * <p>
     * immutableSortedSet.
     * </p>
     *
     * @return a newly created empty {@link java.util.SortedSet} Convenience method
     *         for {@link java.util.Collections#emptySortedSet()}
     * @param <E> a E class
     */
    public static <E> SortedSet<E> immutableSortedSet() {
        return Collections.emptySortedSet();
    }

    /**
     * Creates an <i>immutable</i> {@code SortedSet} instance containing the given
     * elements.
     *
     * @param element to be wrapped, must not be null
     * @return the <i>immutable</i> {@link java.util.Set} with the given elements
     * @param <E> a E class
     */
    public static <E> SortedSet<E> immutableSortedSet(E element) {
        if (null == element) {
            return Collections.emptySortedSet();
        }
        return Collections.unmodifiableSortedSet(mutableSortedSet(element));
    }

    /**
     * Creates an <i>immutable</i> {@code SortedSet} instance containing the given
     * elements.
     *
     * @param elements to be wrapped, must not be null
     * @return the <i>immutable</i> {@link java.util.Set} with the given elements
     * @param <E> a E class
     */
    @SafeVarargs
    public static <E> SortedSet<E> immutableSortedSet(E... elements) {
        return Collections.unmodifiableSortedSet(mutableSortedSet(elements));
    }

    /**
     * Creates an <i>immutable</i> {@code SortedSet} instance containing the given
     * elements.
     *
     * @param elements to be wrapped, must not be null
     * @return the <i>immutable</i> {@link java.util.Set} with the given elements
     * @param <E> a E class
     */
    public static <E> SortedSet<E> immutableSortedSet(Iterable<? extends E> elements) {
        return Collections.unmodifiableSortedSet(mutableSortedSet(elements));
    }

    /**
     * Creates an <i>immutable</i> {@code SortedSet} instance containing the given
     * elements.
     *
     * @param elements to be wrapped, must not be null
     * @return the <i>immutable</i> {@link java.util.Set} with the given elements
     * @param <E> a E class
     */
    public static <E> SortedSet<E> immutableSortedSet(Iterator<? extends E> elements) {
        return Collections.unmodifiableSortedSet(mutableSortedSet(elements));
    }

    /**
     * Creates an <i>immutable</i> {@code SortedSet} instance containing the given
     * elements. <em>Caution:</em> The stream will be consumed by this operation
     *
     * @param elements to be wrapped, must not be null
     * @return the <i>immutable</i> {@link java.util.Set} with the given elements
     * @param <E> a E class
     */
    public static <E> SortedSet<E> immutableSortedSet(Stream<? extends E> elements) {
        return Collections.unmodifiableSortedSet(mutableSortedSet(elements));
    }

    /**
     * <p>
     * mutableMap.
     * </p>
     *
     * @return an empty <i>mutable</i> Map
     * @param <K> a K class
     * @param <V> a V class
     */
    public static <K, V> Map<K, V> mutableMap() {
        return new HashMap<>();
    }

    /**
     * Convenience method for the inline creation of a map with values
     *
     * @param k key to be added
     * @param v value to be added
     * @return a <i>mutable</i> Map with the given elements
     * @param <K> a K class
     * @param <V> a V class
     */
    public static <K, V> Map<K, V> mutableMap(K k, V v) {
        Map<K, V> map = new HashMap<>();
        map.put(k, v);
        return map;
    }

    /**
     * Convenience method for the inline creation of a map with values
     *
     * @param k1 key to be added
     * @param v1 value to be added
     * @param k2 key to be added
     * @param v2 value to be added
     * @return a <i>mutable</i> Map with the given elements
     * @param <K> a K class
     * @param <V> a V class
     */
    public static <K, V> Map<K, V> mutableMap(K k1, V v1, K k2, V v2) {
        Map<K, V> map = new HashMap<>();
        map.put(k1, v1);
        map.put(k2, v2);
        return map;
    }

    /**
     * Convenience method for the inline creation of a map with values
     *
     * @param k1 key to be added
     * @param v1 value to be added
     * @param k2 key to be added
     * @param v2 value to be added
     * @param k3 key to be added
     * @param v3 value to be added
     * @return a <i>mutable</i> Map with the given elements
     * @param <K> a K class
     * @param <V> a V class
     */
    public static <K, V> Map<K, V> mutableMap(K k1, V v1, K k2, V v2, K k3, V v3) {
        Map<K, V> map = new HashMap<>();
        map.put(k1, v1);
        map.put(k2, v2);
        map.put(k3, v3);
        return map;
    }

    /**
     * Convenience method for the inline creation of a map with values
     *
     * @param k1 key to be added
     * @param v1 value to be added
     * @param k2 key to be added
     * @param v2 value to be added
     * @param k3 key to be added
     * @param v3 value to be added
     * @param k4 key to be added
     * @param v4 value to be added
     * @return a <i>mutable</i> Map with the given elements
     * @param <K> a K class
     * @param <V> a V class
     */
    @SuppressWarnings("squid:S00107") // owolff: Number of parameters match to the use-case
    public static <K, V> Map<K, V> mutableMap(K k1, V v1, K k2, V v2, K k3, V v3, K k4, V v4) {
        Map<K, V> map = new HashMap<>();
        map.put(k1, v1);
        map.put(k2, v2);
        map.put(k3, v3);
        map.put(k4, v4);
        return map;
    }

    /**
     * <p>
     * immutableMap.
     * </p>
     *
     * @return an empty <i>mutable</i> Map
     * @param <K> a K class
     * @param <V> a V class
     */
    public static <K, V> Map<K, V> immutableMap() {
        return Collections.emptyMap();
    }

    /**
     * Shorthand to {@link java.util.Collections#unmodifiableMap(Map)}
     *
     * @param source a {@link java.util.Map} object
     * @return an <i>immutable</i> Map with the given elements
     * @param <K> a K class
     * @param <V> a V class
     */
    public static <K, V> Map<K, V> immutableMap(Map<K, V> source) {
        return Collections.unmodifiableMap(source);
    }

    /**
     * Copies the entries of the given map stream into a new map which is then
     * returned as an unmodifiable map.
     *
     * @param elements to be copied
     * @param <K>      key type
     * @param <V>      value type
     * @return unmodifiable map with entries form the given stream
     */
    public static <K, V> Map<K, V> immutableMap(Stream<Map.Entry<K, V>> elements) {
        final Map<K, V> map = mutableMap();
        elements.forEach(entry -> map.put(entry.getKey(), entry.getValue()));
        return Collections.unmodifiableMap(map);
    }

    /**
     * Convenience method for the inline creation of a map with values
     *
     * @param k key to be added
     * @param v value to be added
     * @return an <i>immutable</i> Map with the given elements
     * @param <K> a K class
     * @param <V> a V class
     */
    public static <K, V> Map<K, V> immutableMap(K k, V v) {
        Map<K, V> map = mutableMap();
        map.put(k, v);
        return Collections.unmodifiableMap(map);
    }

    /**
     * Convenience method for the inline creation of a map with values
     *
     * @param k1 key to be added
     * @param v1 value to be added
     * @param k2 key to be added
     * @param v2 value to be added
     * @return an <i>immutable</i> Map with the given elements
     * @param <K> a K class
     * @param <V> a V class
     */
    public static <K, V> Map<K, V> immutableMap(K k1, V v1, K k2, V v2) {
        Map<K, V> map = mutableMap();
        map.put(k1, v1);
        map.put(k2, v2);
        return Collections.unmodifiableMap(map);
    }

    /**
     * Convenience method for the inline creation of a map with values
     *
     * @param k1 key to be added
     * @param v1 value to be added
     * @param k2 key to be added
     * @param v2 value to be added
     * @param k3 key to be added
     * @param v3 value to be added
     * @return an <i>immutable</i> Map with the given elements
     * @param <K> a K class
     * @param <V> a V class
     */
    public static <K, V> Map<K, V> immutableMap(K k1, V v1, K k2, V v2, K k3, V v3) {
        Map<K, V> map = mutableMap();
        map.put(k1, v1);
        map.put(k2, v2);
        map.put(k3, v3);
        return Collections.unmodifiableMap(map);
    }

    /**
     * Convenience method for the inline creation of a map with values
     *
     * @param k1 key to be added
     * @param v1 value to be added
     * @param k2 key to be added
     * @param v2 value to be added
     * @param k3 key to be added
     * @param v3 value to be added
     * @param k4 key to be added
     * @param v4 value to be added
     * @return an <i>immutable</i> Map with the given elements
     * @param <K> a K class
     * @param <V> a V class
     */
    @SuppressWarnings("squid:S00107") // owolff: Number of parameters match to the use-case
    public static <K, V> Map<K, V> immutableMap(K k1, V v1, K k2, V v2, K k3, V v3, K k4, V v4) {
        Map<K, V> map = mutableMap();
        map.put(k1, v1);
        map.put(k2, v2);
        map.put(k3, v3);
        map.put(k4, v4);
        return Collections.unmodifiableMap(map);
    }

}
