package de.icw.util.collect;

import static de.icw.util.collect.MoreCollections.isEmpty;

import java.util.ArrayList;
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

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;

/**
 * Provides a number of utilities simplifying the task of creating populated {@link Collection}s. In
 * essence its doing the same compared to the corresponding {@link com.google.common.collect} types
 * but with different semantics (like naming, types) and is designed as a one stop utility class.
 * It differentiates between the sub-types and mutability / immutability. This class is
 * complementary to the corresponding guava types.
 *
 * @author Oliver Wolff
 *
 */
public class CollectionLiterals {

    /**
     * @return a newly created empty {@link ArrayList}
     */
    public static <E> List<E> mutableList() {
        return new ArrayList<>();
    }

    /**
     * Creates a <i>mutable</i> {@code List} instance containing the given elements.
     *
     * @param elements to be added
     * @return the <i>mutable</i> {@link List} with the given elements
     */
    @SafeVarargs
    public static <E> List<E> mutableList(E... elements) {
        if (isEmpty(elements)) {
            return new ArrayList<>();
        }
        return Lists.newArrayList(elements);
    }

    /**
     * Creates a <i>mutable</i> {@code List} instance containing the given element
     *
     * @param element to be added
     * @return the <i>mutable</i> {@link List} with the given element
     */
    public static <E> List<E> mutableList(E element) {
        return Lists.newArrayList(element);
    }

    /**
     * Creates a <i>mutable</i> {@code List} instance containing the given elements.
     *
     * @param elements to be added. If it is null and empty <i>mutable</i> list will be returned
     * @return the <i>mutable</i> {@link List} with the given elements
     */
    public static <E> List<E> mutableList(Iterable<? extends E> elements) {
        if (isEmpty(elements)) {
            return new ArrayList<>();
        }
        return Lists.newArrayList(elements);
    }

    /**
     * Creates a <i>mutable</i> {@code List} instance containing the given elements.
     *
     * @param elements to be added. If it is null and empty <i>mutable</i> list will be returned
     * @return the <i>mutable</i> {@link List} with the given elements
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
     * @param elements to be added. If it is null an empty <i>mutable</i> {@code List} will be
     *            returned
     * @return the <i>mutable</i> {@code List} with the given elements
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
     * @param elements to be added. If it is null and empty <i>mutable</i> list will be returned
     * @return the <i>mutable</i> {@link List} with the given elements
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
     * {@link Collections#emptyList()}
     *
     * @return the <i>immutable</i> {@link List} with the given elements
     */
    public static <E> List<E> immutableList() {
        return Collections.emptyList();
    }

    /**
     * Creates an <i>immutable</i> {@code List} instance containing the given elements.
     *
     * @param elements to be wrapped, must not be null
     * @return the <i>immutable</i> {@link List} with the given elements
     */
    @SafeVarargs
    public static <E> List<E> immutableList(E... elements) {
        if (isEmpty(elements)) {
            return Collections.emptyList();
        }
        return ImmutableList.copyOf(elements);
    }

    /**
     * Creates an <i>immutable</i> {@code List} instance containing the given element.
     *
     * @param element to be wrapped, must not be null
     * @return the <i>immutable</i> {@link List} with the given elements
     */
    public static <E> List<E> immutableList(E element) {
        if (null == element) {
            return Collections.emptyList();
        }
        return ImmutableList.of(element);
    }

    /**
     * Creates an <i>immutable</i> {@code List} instance containing the given elements.
     *
     * @param elements to be wrapped, must not be null
     * @return the <i>immutable</i> {@link List} with the given elements
     */
    public static <E> List<E> immutableList(Iterable<? extends E> elements) {
        if (isEmpty(elements)) {
            return Collections.emptyList();
        }
        return ImmutableList.copyOf(elements);
    }

    /**
     * Creates an <i>immutable</i> {@code List} instance containing the given elements.
     *
     * @param elements to be wrapped, must not be null
     * @return the <i>immutable</i> {@link List} with the given elements
     */
    public static <E> List<E> immutableList(Collection<? extends E> elements) {
        if (isEmpty(elements)) {
            return Collections.emptyList();
        }
        if (elements instanceof List) {
            return Collections.unmodifiableList((List<? extends E>) elements);
        } else {
            return ImmutableList.copyOf(elements);
        }
    }

    /**
     * Creates an <i>immutable</i> {@code List} instance containing the given elements.
     * <em>Caution:</em> The stream will be consumed by this operation
     *
     * @param elements to be wrapped, must not be null
     * @return the <i>immutable</i> {@link List} with the given elements
     */
    public static <E> List<E> immutableList(Stream<? extends E> elements) {
        if (isEmpty(elements)) {
            return Collections.emptyList();
        }
        ImmutableList.Builder<E> builder = ImmutableList.builder();
        elements.forEach(builder::add);
        return builder.build();
    }

    /**
     * Creates an <i>immutable</i> {@code List} instance containing the given elements.
     *
     * @param elements to be wrapped, must not be null
     * @return the <i>immutable</i> {@link List} with the given elements
     */
    public static <E> List<E> immutableList(Iterator<? extends E> elements) {
        if (isEmpty(elements)) {
            return Collections.emptyList();
        }
        return ImmutableList.copyOf(elements);
    }

    /**
     * @return a newly created empty {@link HashSet}
     */
    public static <E> Set<E> mutableSet() {
        return new HashSet<>();
    }

    /**
     * @param element to be added. If it is {@code null} it will not be added
     * @return a newly created empty {@link HashSet} with the given elements
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
     * @param elements to be added
     * @return a newly created empty {@link HashSet} with the given elements
     */
    @SafeVarargs
    public static <E> Set<E> mutableSet(E... elements) {
        if (isEmpty(elements)) {
            return new HashSet<>();
        }
        return Sets.newHashSet(elements);
    }

    /**
     * Creates a <i>mutable</i> {@code Set} instance containing the given elements.
     *
     * @param elements to be added. If it is null and empty <i>mutable</i> list will be returned
     * @return the <i>mutable</i> {@link Set} with the given elements
     */
    public static <E> Set<E> mutableSet(Iterable<? extends E> elements) {
        if (isEmpty(elements)) {
            return new HashSet<>();
        }
        return Sets.newHashSet(elements);
    }

    /**
     * Creates a <i>mutable</i> {@code Set} instance containing the given elements.
     *
     * @param elements to be added. If it is null and empty <i>mutable</i> list will be returned
     * @return the <i>mutable</i> {@link Set} with the given elements
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
     * @param elements to be added. If it is null and empty <i>mutable</i> list will be returned
     * @return the <i>mutable</i> {@link Set} with the given elements
     */
    public static <E> Set<E> mutableSet(Iterator<? extends E> elements) {
        if (isEmpty(elements)) {
            return new HashSet<>();
        }
        return Sets.newHashSet(elements);
    }

    /**
     * Creates a <i>mutable</i> {@code Set} instance containing the given elements.
     * <em>Caution:</em> The stream will be consumed by this operation
     *
     * @param elements to be added. If it is null and empty <i>mutable</i> {@link Sets} will be
     *            returned
     * @return the <i>mutable</i> {@link Set} with the given elements
     */
    public static <E> Set<E> mutableSet(Stream<? extends E> elements) {
        if (isEmpty(elements)) {
            return new HashSet<>();
        }
        Set<E> set = new HashSet<>();
        elements.forEach(set::add);
        return set;
    }

    /**
     * @return a newly created empty {@link HashSet} Convenience method for
     *         {@link Collections#emptySet()}
     */
    public static <E> Set<E> immutableSet() {
        return Collections.emptySet();
    }

    /**
     * Creates an <i>immutable</i> {@code Set} instance containing the given elements.
     *
     * @param element to be wrapped, must not be null
     * @return the <i>immutable</i> {@link Set} with the given elements
     */
    public static <E> Set<E> immutableSet(E element) {
        if (null == element) {
            return Collections.emptySet();
        }
        return ImmutableSet.of(element);
    }

    /**
     * Creates an <i>immutable</i> {@code Set} instance containing the given elements.
     *
     * @param elements to be wrapped, must not be null
     * @return the <i>immutable</i> {@link Set} with the given elements
     */
    @SafeVarargs
    public static <E> Set<E> immutableSet(E... elements) {
        if (isEmpty(elements)) {
            return Collections.emptySet();
        }
        return ImmutableSet.copyOf(elements);
    }

    /**
     * Creates an <i>immutable</i> {@code Set} instance containing the given elements.
     *
     * @param elements to be wrapped
     * @return the <i>immutable</i> {@link Set} with the given elements
     */
    public static <E> Set<E> immutableSet(Iterable<? extends E> elements) {
        if (isEmpty(elements)) {
            return Collections.emptySet();
        }
        return ImmutableSet.copyOf(elements);
    }

    /**
     * Creates an <i>immutable</i> {@code Set} instance containing the given elements.
     *
     * @param elements to be wrapped, must not be null
     * @return the <i>immutable</i> {@link Set} with the given elements
     */
    public static <E> Set<E> immutableSet(Iterator<? extends E> elements) {
        if (isEmpty(elements)) {
            return Collections.emptySet();
        }
        return ImmutableSet.copyOf(elements);
    }

    /**
     * Creates an <i>immutable</i> {@code Set} instance containing the given elements.
     * <em>Caution:</em> The stream will be consumed by this operation
     *
     * @param elements to be wrapped, must not be null
     * @return the <i>immutable</i> {@link Set} with the given elements
     */
    public static <E> Set<E> immutableSet(Stream<? extends E> elements) {
        if (isEmpty(elements)) {
            return Collections.emptySet();
        }
        ImmutableSet.Builder<E> builder = ImmutableSet.builder();
        elements.forEach(builder::add);
        return builder.build();
    }

    /**
     * @return a newly created empty {@link TreeSet}
     */
    public static <E> SortedSet<E> mutableSortedSet() {
        return new TreeSet<>();
    }

    /**
     * @param element to be added. If it is {@code null} an empty {@link SortedSet} will be returned
     * @return a newly created empty {@link TreeSet} with the given element
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
     * @param elements to be added
     * @return a newly created empty {@link TreeSet} with the given elements
     */
    @SafeVarargs
    public static <E> SortedSet<E> mutableSortedSet(E... elements) {
        SortedSet<E> set = new TreeSet<>();
        if (isEmpty(elements)) {
            return set;
        }
        for (int i = 0; i < elements.length; i++) {
            set.add(elements[i]);
        }
        return set;
    }

    /**
     * Creates a <i>mutable</i> {@code SortedSet} instance containing the given elements.
     *
     * @param elements to be added. If it is null and empty <i>mutable</i> list will be returned
     * @return the <i>mutable</i> {@link TreeSet} with the given elements
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
     * Creates a <i>mutable</i> {@code SortedSet} instance containing the given elements.
     *
     * @param elements to be added. If it is null and empty <i>mutable</i> list will be returned
     * @return the <i>mutable</i> {@link Set} with the given elements
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
     * Creates a <i>mutable</i> {@code SortedSet} instance containing the given elements.
     * <em>Caution:</em> The stream will be consumed by this operation
     *
     * @param elements to be added. If it is null and empty <i>mutable</i> list will be returned
     * @return the <i>mutable</i> {@link Set} with the given elements
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
     * @return a newly created empty {@link SortedSet} Convenience method for
     *         {@link Collections#emptySortedSet()}
     */
    public static <E> SortedSet<E> immutableSortedSet() {
        return Collections.emptySortedSet();
    }

    /**
     * Creates an <i>immutable</i> {@code SortedSet} instance containing the given elements.
     *
     * @param element to be wrapped, must not be null
     * @return the <i>immutable</i> {@link Set} with the given elements
     */
    public static <E> SortedSet<E> immutableSortedSet(E element) {
        if (null == element) {
            return Collections.emptySortedSet();
        }
        return Collections.unmodifiableSortedSet(mutableSortedSet(element));
    }

    /**
     * Creates an <i>immutable</i> {@code SortedSet} instance containing the given elements.
     *
     * @param elements to be wrapped, must not be null
     * @return the <i>immutable</i> {@link Set} with the given elements
     */
    @SafeVarargs
    public static <E> SortedSet<E> immutableSortedSet(E... elements) {
        return Collections.unmodifiableSortedSet(mutableSortedSet(elements));
    }

    /**
     * Creates an <i>immutable</i> {@code SortedSet} instance containing the given elements.
     *
     * @param elements to be wrapped, must not be null
     * @return the <i>immutable</i> {@link Set} with the given elements
     */
    public static <E> SortedSet<E> immutableSortedSet(Iterable<? extends E> elements) {
        return Collections.unmodifiableSortedSet(mutableSortedSet(elements));
    }

    /**
     * Creates an <i>immutable</i> {@code SortedSet} instance containing the given elements.
     *
     * @param elements to be wrapped, must not be null
     * @return the <i>immutable</i> {@link Set} with the given elements
     */
    public static <E> SortedSet<E> immutableSortedSet(Iterator<? extends E> elements) {
        return Collections.unmodifiableSortedSet(mutableSortedSet(elements));
    }

    /**
     * Creates an <i>immutable</i> {@code SortedSet} instance containing the given elements.
     * <em>Caution:</em> The stream will be consumed by this operation
     *
     * @param elements to be wrapped, must not be null
     * @return the <i>immutable</i> {@link Set} with the given elements
     */
    public static <E> SortedSet<E> immutableSortedSet(Stream<? extends E> elements) {
        return Collections.unmodifiableSortedSet(mutableSortedSet(elements));
    }

    /**
     * @return an empty <i>mutable</i> Map
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
     * @return an empty <i>mutable</i> Map
     */
    public static <K, V> Map<K, V> immutableMap() {
        return Collections.emptyMap();
    }

    /**
     * Shorthand to {@link Collections#unmodifiableMap(Map)}
     *
     * @param source
     * @return an <i>immutable</i> Map with the given elements
     */
    public static <K, V> Map<K, V> immutableMap(Map<K, V> source) {
        return Collections.unmodifiableMap(source);
    }

    /**
     * Convenience method for the inline creation of a map with values
     *
     * @param k key to be added
     * @param v value to be added
     * @return an <i>immutable</i> Map with the given elements
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

    private CollectionLiterals() {
        // Highlander
    }
}
