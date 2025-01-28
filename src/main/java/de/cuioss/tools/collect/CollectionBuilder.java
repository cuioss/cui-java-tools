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

import static de.cuioss.tools.collect.CollectionLiterals.mutableList;
import static java.util.Objects.requireNonNull;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.NavigableSet;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.stream.Stream;

/**
 * <h2>Overview</h2>
 * Builder for creating {@link java.util.Collection}s providing some convenience methods.
 * The class writes everything through into the contained collector. Using the default
 * constructor a newly created {@link java.util.ArrayList} will be used as collector,
 * but you can pass your own collector as constructor-argument. Of course this should
 * be mutable in order to work.
 * 
 * <h3>Handling of null-values</h3>
 * <p>
 * As default {@code null} values are ignored. This behavior can be changed by
 * calling {@link #addNullValues(boolean)}. <em>Caution:</em> In case of using one
 * of the {@link #copyFrom(Collection)} methods for instantiation the
 * {@code null} values will not be checked in that way
 * </p>
 * 
 * <h3>Basic Usage Examples</h3>
 * <pre>
 * // Create an immutable list
 * List&lt;String&gt; immutableList = new CollectionBuilder&lt;String&gt;()
 *     .add("first")
 *     .add("second")
 *     .add(mutableList("third", "fourth"))
 *     .toImmutableList();
 * 
 * // Create a mutable set
 * Set&lt;String&gt; mutableSet = new CollectionBuilder&lt;String&gt;()
 *     .add("unique1")
 *     .add("unique2")
 *     .toMutableSet();
 * </pre>
 * 
 * <h3>Advanced Usage Examples</h3>
 * 
 * <h4>1. Working with Null Values</h4>
 * <pre>
 * // Configure builder to accept null values
 * List&lt;String&gt; withNulls = new CollectionBuilder&lt;String&gt;()
 *     .addNullValues(true)
 *     .add("first")
 *     .add(null)
 *     .add("third")
 *     .toMutableList();
 * // Result: ["first", null, "third"]
 * </pre>
 * 
 * <h4>2. Copying and Transforming Collections</h4>
 * <pre>
 * // Copy existing collection and add elements
 * List&lt;String&gt; source = Arrays.asList("one", "two");
 * List&lt;String&gt; enhanced = CollectionBuilder.copyFrom(source)
 *     .add("three")
 *     .add("four")
 *     .toImmutableList();
 * 
 * // Transform to different collection type
 * Set&lt;String&gt; asSet = CollectionBuilder.copyFrom(source)
 *     .toMutableSet();
 * </pre>
 * 
 * <h4>3. Working with Streams and Optional</h4>
 * <pre>
 * // Adding elements from a stream
 * Stream&lt;String&gt; stream = Stream.of("a", "b", "c");
 * List&lt;String&gt; fromStream = new CollectionBuilder&lt;String&gt;()
 *     .add(stream)
 *     .toMutableList();
 * 
 * // Working with Optional values
 * Optional&lt;String&gt; maybeValue = Optional.of("value");
 * List&lt;String&gt; withOptional = new CollectionBuilder&lt;String&gt;()
 *     .add(maybeValue)
 *     .add(Optional.empty())  // Will be ignored by default
 *     .toMutableList();
 * </pre>
 * 
 * <h4>4. Sorting Collections</h4>
 * <pre>
 * // Create a sorted list
 * List&lt;Integer&gt; sorted = new CollectionBuilder&lt;Integer&gt;()
 *     .add(3, 1, 4, 1, 5)
 *     .sort(Comparator.naturalOrder())
 *     .toImmutableList();
 * // Result: [1, 1, 3, 4, 5]
 * 
 * // Custom sorting
 * List&lt;String&gt; sortedByLength = new CollectionBuilder&lt;String&gt;()
 *     .add("aaa", "a", "aa")
 *     .sort(Comparator.comparing(String::length))
 *     .toImmutableList();
 * // Result: ["a", "aa", "aaa"]
 * </pre>
 * 
 * <h4>5. Thread-Safe Collections</h4>
 * <pre>
 * // Create a concurrent list
 * List&lt;String&gt; concurrentList = new CollectionBuilder&lt;String&gt;()
 *     .add("thread", "safe", "list")
 *     .toConcurrentList();
 * 
 * // Create a concurrent navigable set
 * NavigableSet&lt;Integer&gt; concurrentSet = new CollectionBuilder&lt;Integer&gt;()
 *     .add(1, 2, 3)
 *     .toConcurrentNavigableSet();
 * </pre>
 * 
 * @author Oliver Wolff
 * @param <E> The type of the contained {@link java.util.Collection}
 */
@EqualsAndHashCode
@ToString
public final class CollectionBuilder<E> implements Iterable<E> {

    private final Collection<E> collector;

    /**
     * If set to {@code true} {@code null} elements are added to the contained
     * collector, if {@code false}, default value, {@code null} values are ignored.
     */
    @Getter
    private boolean addNullValues = false;

    /**
     * <p>
     * Constructor for CollectionBuilder.
     * </p>
     *
     * @param collector to be used for storage. Must not be null
     */
    public CollectionBuilder(Collection<E> collector) {
        this.collector = requireNonNull(collector);
    }

    /**
     * Default Constructor initializing the collector with an
     * {@link java.util.ArrayList}
     */
    public CollectionBuilder() {
        this(new ArrayList<>());
    }

    /**
     * <p>
     * addNullValues.
     * </p>
     *
     * @param addNullValues If set to {@code true} {@code null} elements are added
     *                      to the contained collector, if {@code false}, default
     *                      value, {@code null} values are ignored.
     * @return the instance itself in order to use it in a fluent way.
     */
    public CollectionBuilder<E> addNullValues(boolean addNullValues) {
        this.addNullValues = addNullValues;
        return this;
    }

    /**
     * <p>
     * size.
     * </p>
     *
     * @return the size of the contained Collection
     */
    public int size() {
        return collector.size();
    }

    /**
     * <p>
     * isEmpty.
     * </p>
     *
     * @return see {@link java.util.Collection#isEmpty()}
     */
    public boolean isEmpty() {
        return collector.isEmpty();
    }

    /**
     * <p>
     * contains.
     * </p>
     *
     * @param o a {@link java.lang.Object} object
     * @return see {@link java.util.Collection#isEmpty()}
     */
    public boolean contains(Object o) {
        return collector.contains(o);
    }

    /** {@inheritDoc} */
    @Override
    public Iterator<E> iterator() {
        return collector.iterator();
    }

    /**
     * <p>
     * stream.
     * </p>
     *
     * @return a {@link java.util.stream.Stream} on the contained objects
     */
    public Stream<E> stream() {
        return collector.stream();
    }

    /**
     * <p>
     * add.
     * </p>
     *
     * @param e the element to be added
     * @return the instance itself in order to use it in a fluent way.
     *         <em>Caution:</em> with this call the return value of
     *         {@link java.util.Collection#add(Object)} will be ignored.
     */
    public CollectionBuilder<E> add(E e) {
        if (addNullValues || null != e) {
            collector.add(e);
        }
        return this;
    }

    /**
     * <p>
     * add.
     * </p>
     *
     * @param elements to be added
     * @return the instance itself in order to use it in a fluent way.
     *         <em>Caution:</em> with this call the return value of
     *         {@link java.util.Collection#add(Object)} will be ignored.
     */
    @SafeVarargs
    public final CollectionBuilder<E> add(E... elements) {
        if (!MoreCollections.isEmpty(elements)) {
            for (E element : elements) {
                add(element);
            }
        }
        return this;
    }

    /**
     * <p>
     * add.
     * </p>
     *
     * @param elements to be added
     * @return the instance itself in order to use it in a fluent way.
     *         <em>Caution:</em> with this call the return value of
     *         {@link java.util.Collection#add(Object)} will be ignored.
     */
    public CollectionBuilder<E> add(Iterable<E> elements) {
        if (!MoreCollections.isEmpty(elements)) {
            elements.forEach(this::add);
        }
        return this;
    }

    /**
     * <p>
     * add.
     * </p>
     *
     * @param elements to be added
     * @return the instance itself in order to use it in a fluent way.
     *         <em>Caution:</em> with this call the return value of
     *         {@link java.util.Collection#add(Object)} will be ignored.
     */
    public CollectionBuilder<E> add(Collection<E> elements) {
        if (!MoreCollections.isEmpty(elements)) {
            elements.forEach(this::add);
        }
        return this;
    }

    /**
     * <p>
     * add.
     * </p>
     *
     * @param element to be added if present. <em>Caution</em>: passing an
     *                {@link java.util.Optional} parameter is a not a good thing to
     *                do, I know, but in this context it is quite convenient: Don't
     *                do this at home
     * @return the instance itself in order to use it in a fluent way.
     *         <em>Caution:</em> with this call the return value of
     *         {@link java.util.Collection#add(Object)} will be ignored.
     */
    public CollectionBuilder<E> add(Optional<E> element) {
        element.ifPresent(this::add);
        return this;
    }

    /**
     * <p>
     * add.
     * </p>
     *
     * @param elements to be added
     * @return the instance itself in order to use it in a fluent way.
     *         <em>Caution:</em> with this call the return value of
     *         {@link java.util.Collection#add(Object)} will be ignored.
     */
    public CollectionBuilder<E> add(Stream<E> elements) {
        if (!MoreCollections.isEmpty(elements)) {
            elements.forEach(this::add);
        }
        return this;
    }

    /**
     * Sorts the contained Collection.
     *
     * @param comparator must not be null.
     * @return the instance itself in order to use it in a fluent way.
     */
    public CollectionBuilder<E> sort(Comparator<? super E> comparator) {
        if (collector instanceof List) {
            Collections.sort((List<E>) collector, comparator);
        } else {
            List<E> sorter = new ArrayList<>(collector);
            Collections.sort(sorter, comparator);
            collector.clear();
            collector.addAll(sorter);
        }
        return this;
    }

    /**
     * <p>
     * toMutableList.
     * </p>
     *
     * @return a mutable {@link java.util.List} representation of the builders
     *         content, the actual implementation is an {@link java.util.ArrayList}
     */
    public List<E> toMutableList() {
        return new ArrayList<>(collector);
    }

    /**
     * <p>
     * toImmutableList.
     * </p>
     *
     * @return an immutable {@link java.util.List} representation of the builders
     *         content, the actual implementation calls
     *         {@link java.util.Collections#unmodifiableList(List)}. The underlying
     *         {@link java.util.Collection} will be copied by calling
     *         {@link #toMutableList()}
     */
    public List<E> toImmutableList() {
        return Collections.unmodifiableList(toMutableList());
    }

    /**
     * <p>
     * toMutableSet.
     * </p>
     *
     * @return a mutable {@link java.util.Set} representation of the builders
     *         content, the actual implementation is an {@link java.util.HashSet}
     */
    public Set<E> toMutableSet() {
        return new HashSet<>(collector);
    }

    /**
     * <p>
     * toImmutableSet.
     * </p>
     *
     * @return an immutable {@link java.util.Set} representation of the builders
     *         content, the actual implementation calls
     *         {@link java.util.Collections#unmodifiableList(List)}. The underlying
     *         {@link java.util.Collection} will be copied by calling
     *         {@link #toMutableSet()}
     */
    public Set<E> toImmutableSet() {
        return Collections.unmodifiableSet(toMutableSet());
    }

    /**
     * <p>
     * toConcurrentList.
     * </p>
     *
     * @return a concurrent mutable {@link java.util.List} representation of the
     *         builders content, the actual implementation is an
     *         {@link java.util.concurrent.CopyOnWriteArrayList}
     */
    public List<E> toConcurrentList() {
        return new CopyOnWriteArrayList<>(collector);
    }

    /**
     * <p>
     * toConcurrentSet.
     * </p>
     *
     * @return a concurrent mutable {@link java.util.Set} representation of the
     *         builders content, the actual implementation is an
     *         {@link java.util.concurrent.CopyOnWriteArraySet}
     */
    public Set<E> toConcurrentSet() {
        return new CopyOnWriteArraySet<>(collector);
    }

    /**
     * <p>
     * toMutableNavigableSet.
     * </p>
     *
     * @return a mutable {@link java.util.NavigableSet} representation of the
     *         builders content, the actual implementation is an
     *         {@link java.util.TreeSet}. The assumption is that the Actual type is
     *         at least {@link java.lang.Comparable}
     */
    public NavigableSet<E> toMutableNavigableSet() {
        return new TreeSet<>(collector);
    }

    /**
     * <p>
     * toImmutableNavigableSet.
     * </p>
     *
     * @return an immutable {@link java.util.NavigableSet} representation of the
     *         builders content, the actual implementation is an
     *         {@link java.util.TreeSet} wrapped by
     *         {@link java.util.Collections#unmodifiableNavigableSet(NavigableSet)}.
     *         The assumption is that the Actual type is at least
     *         {@link java.lang.Comparable}
     */
    public NavigableSet<E> toImmutableNavigableSet() {
        return Collections.unmodifiableNavigableSet(toMutableNavigableSet());
    }

    /**
     * <p>
     * toConcurrentNavigableSet.
     * </p>
     *
     * @return a mutable {@link java.util.NavigableSet} representation of the
     *         builders content, the actual implementation is an
     *         {@link java.util.concurrent.ConcurrentSkipListSet}. The assumption is
     *         that the actual type is at least {@link java.lang.Comparable}
     */
    public NavigableSet<E> toConcurrentNavigableSet() {
        return new ConcurrentSkipListSet<>(collector);
    }

    /**
     * <p>
     * toArray.
     * </p>
     *
     * @param targetType identifying the concrete ArrayType
     * @return an array representation of the builders content
     */
    @SuppressWarnings("unchecked")
    public E[] toArray(Class<? super E> targetType) {
        if (isEmpty()) {
            return (E[]) Array.newInstance(targetType, 0);
        }
        var target = (E[]) Array.newInstance(targetType, size());
        return collector.toArray(target);
    }

    /**
     * Clears the elements in the collector
     *
     * @return the instance itself in order to use it in a fluent way.
     */
    public CollectionBuilder<E> clear() {
        collector.clear();
        return this;
    }

    /**
     * Creates an Instance of {@link de.cuioss.tools.collect.CollectionBuilder} by
     * copying the content of the given source <em>Caution:</em> The given source
     * will be used as it is, there will be no filtering as defined within
     * {@link #addNullValues(boolean)}
     *
     * @param source may be null
     * @return the newly created {@link de.cuioss.tools.collect.CollectionBuilder}
     * @param <E> a E class
     */
    public static <E> CollectionBuilder<E> copyFrom(Iterable<? extends E> source) {
        return new CollectionBuilder<>(mutableList(source));
    }

    /**
     * Creates an Instance of {@link de.cuioss.tools.collect.CollectionBuilder} by
     * copying the content of the given source <em>Caution:</em> The given source
     * will be used as it is, there will be no filtering as defined within
     * {@link #addNullValues(boolean)}
     *
     * @param source may be null
     * @return the newly created {@link de.cuioss.tools.collect.CollectionBuilder}
     * @param <E> a E class
     */
    public static <E> CollectionBuilder<E> copyFrom(Iterator<? extends E> source) {
        return new CollectionBuilder<>(mutableList(source));
    }

    /**
     * Creates an Instance of {@link de.cuioss.tools.collect.CollectionBuilder} by
     * copying the content of the given source <em>Caution:</em> The given source
     * will be used as it is, there will be no filtering as defined within
     * {@link #addNullValues(boolean)}
     *
     * @param source may be null
     * @return the newly created {@link de.cuioss.tools.collect.CollectionBuilder}
     * @param <E> a E class
     */
    public static <E> CollectionBuilder<E> copyFrom(Collection<? extends E> source) {
        return new CollectionBuilder<>(mutableList(source));
    }

    /**
     * Creates an Instance of {@link de.cuioss.tools.collect.CollectionBuilder} by
     * copying the content of the given source <em>Caution:</em> The given source
     * will be used as it is, there will be no filtering as defined within
     * {@link #addNullValues(boolean)}
     *
     * @param source may be null
     * @return the newly created {@link de.cuioss.tools.collect.CollectionBuilder}
     * @param <E> a E class
     */
    public static <E> CollectionBuilder<E> copyFrom(Stream<? extends E> source) {
        return new CollectionBuilder<>(mutableList(source));
    }

    /**
     * Creates an Instance of {@link de.cuioss.tools.collect.CollectionBuilder} by
     * copying the content of the given source <em>Caution:</em> The given source
     * will be used as it is, there will be no filtering as defined within
     * {@link #addNullValues(boolean)}
     *
     * @param source may be null
     * @return the newly created {@link de.cuioss.tools.collect.CollectionBuilder}
     * @param <E> a E class
     */
    @SafeVarargs
    public static <E> CollectionBuilder<E> copyFrom(E... source) {
        return new CollectionBuilder<>(mutableList(source));
    }

    /**
     * Creates an Instance of {@link de.cuioss.tools.collect.CollectionBuilder} by
     * copying the content of the given source <em>Caution:</em> The given source
     * will be used as it is, there will be no filtering as defined within
     * {@link #addNullValues(boolean)}
     *
     * @param source may be null
     * @return the newly created {@link de.cuioss.tools.collect.CollectionBuilder}
     * @param <E> a E class
     */
    public static <E> CollectionBuilder<E> copyFrom(E source) {
        return new CollectionBuilder<>(mutableList(source));
    }

}
