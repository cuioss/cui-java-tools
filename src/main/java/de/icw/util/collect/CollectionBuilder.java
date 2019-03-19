package de.icw.util.collect;

import static de.icw.util.collect.CollectionLiterals.mutableList;
import static java.util.Objects.requireNonNull;

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

import com.google.common.base.MoreObjects;

/**
 * Builder for creating {@link Collections}s providing some convenience methods. The class itself
 * contains no state, but writes everything through the contained collector. Using the default
 * constructor a newly created {@link ArrayList} will be used as collector, but you can pass you own
 * collector as constructor-argument
 *
 * @author i001428, Oliver Wolff
 * @param <E> The type of the contained {@link Collection}
 *
 */
public final class CollectionBuilder<E> implements Iterable<E> {

    private Collection<E> collector;

    /**
     * @param collector to be used for storage. Must not be null
     */
    public CollectionBuilder(Collection<E> collector) {
        super();
        this.collector = requireNonNull(collector);
    }

    /**
     * Default Constructor initializing the collector with an {@link ArrayList}
     *
     */
    public CollectionBuilder() {
        this(new ArrayList<>());
    }

    /**
     * @return the size of the contained Collection
     */
    public int size() {
        return collector.size();
    }

    /**
     * @return see {@link Collection#isEmpty()}
     */
    public boolean isEmpty() {
        return collector.isEmpty();
    }

    /**
     * @param o
     * @return see {@link Collection#isEmpty()}
     */
    public boolean contains(Object o) {
        return collector.contains(o);
    }

    @Override
    public Iterator<E> iterator() {
        return collector.iterator();
    }

    /**
     * @param e the element to be added
     * @return the instance itself in order to use it in a fluent way. <em>Caution:</em> with this
     *         call the
     *         return value of {@link Collection#add(Object)} will be ignored.
     */
    public CollectionBuilder<E> add(E e) {
        collector.add(e);
        return this;
    }

    /**
     * @param elements to be added
     * @return the instance itself in order to use it in a fluent way. <em>Caution:</em> with this
     *         call the
     *         return value of {@link Collection#add(Object)} will be ignored.
     */
    public CollectionBuilder<E> add(@SuppressWarnings("unchecked") E... elements) {
        if (!MoreCollections.isEmpty(elements)) {
            for (int i = 0; i < elements.length; i++) {
                add(elements[i]);
            }
        }
        return this;
    }

    /**
     * @param elements to be added
     * @return the instance itself in order to use it in a fluent way. <em>Caution:</em> with this
     *         call the
     *         return value of {@link Collection#add(Object)} will be ignored.
     */
    public CollectionBuilder<E> add(Iterable<E> elements) {
        elements.forEach(collector::add);
        return this;
    }

    /**
     * @param elements to be added
     * @return the instance itself in order to use it in a fluent way. <em>Caution:</em> with this
     *         call the
     *         return value of {@link Collection#add(Object)} will be ignored.
     */
    public CollectionBuilder<E> add(Collection<E> elements) {
        collector.addAll(elements);
        return this;
    }

    /**
     * @param element the element to be added if present
     * @return the instance itself in order to use it in a fluent way. <em>Caution:</em> with this
     *         call the
     *         return value of {@link Collection#add(Object)} will be ignored.
     */
    public CollectionBuilder<E> add(Optional<E> element) {
        element.ifPresent(this::add);
        return this;
    }

    /**
     * @param elements to be added
     * @return the instance itself in order to use it in a fluent way. <em>Caution:</em> with this
     *         call the
     *         return value of {@link Collection#add(Object)} will be ignored.
     */
    public CollectionBuilder<E> add(Stream<E> elements) {
        elements.forEach(collector::add);
        return this;
    }

    /**
     * @param e the element to be added. If it is null it will be ignored
     * @return the instance itself in order to use it in a fluent way. <em>Caution:</em> with this
     *         call the
     *         return value of {@link Collection#add(Object)} will be ignored.
     */
    public CollectionBuilder<E> addIfNotNull(E e) {
        if (null != e) {
            collector.add(e);
        }
        return this;
    }

    /**
     * @param elements to be added. {@code null} values will be ignored
     * @return the instance itself in order to use it in a fluent way. <em>Caution:</em> with this
     *         call the
     *         return value of {@link Collection#add(Object)} will be ignored.
     */
    public CollectionBuilder<E> addIfNotNull(@SuppressWarnings("unchecked") E... elements) {
        if (!MoreCollections.isEmpty(elements)) {
            for (int i = 0; i < elements.length; i++) {
                addIfNotNull(elements[i]);
            }
        }
        return this;
    }

    /**
     * @param elements to be added. {@code null} values will be ignored
     * @return the instance itself in order to use it in a fluent way. <em>Caution:</em> with this
     *         call the
     *         return value of {@link Collection#add(Object)} will be ignored.
     */
    public CollectionBuilder<E> addIfNotNull(Iterable<E> elements) {
        elements.forEach(this::addIfNotNull);
        return this;
    }

    /**
     * @param elements to be added. {@code null} values will be ignored
     * @return the instance itself in order to use it in a fluent way. <em>Caution:</em> with this
     *         call the
     *         return value of {@link Collection#add(Object)} will be ignored.
     */
    public CollectionBuilder<E> addIfNotNull(Collection<E> elements) {
        elements.forEach(this::addIfNotNull);
        return this;
    }

    /**
     * @param elements to be added. {@code null} values will be ignored
     * @return the instance itself in order to use it in a fluent way. <em>Caution:</em> with this
     *         call the
     *         return value of {@link Collection#add(Object)} will be ignored.
     */
    public CollectionBuilder<E> addIfNotNull(Stream<E> elements) {
        elements.forEach(this::addIfNotNull);
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
     * @return a mutable {@link List} representation of the builders content, the actual
     *         implementation is an {@link ArrayList}
     */
    public List<E> toMutableList() {
        return new ArrayList<>(collector);
    }

    /**
     * @return an immutable {@link List} representation of the builders content, the actual
     *         implementation calls {@link Collections#unmodifiableList(List)}. The underlying
     *         {@link Collection} will be copied by calling {@link #toMutableList()}
     */
    public List<E> toImmutableList() {
        return Collections.unmodifiableList(toMutableList());
    }

    /**
     * @return a mutable {@link Set} representation of the builders content, the actual
     *         implementation is an {@link HashSet}
     */
    public Set<E> toMutableSet() {
        return new HashSet<>(collector);
    }

    /**
     * @return an immutable {@link Set} representation of the builders content, the actual
     *         implementation calls {@link Collections#unmodifiableList(List)}. The underlying
     *         {@link Collection} will be copied by calling {@link #toMutableSet()}
     */
    public Set<E> toImmutableSet() {
        return Collections.unmodifiableSet(toMutableSet());
    }

    /**
     * @return a concurrent mutable {@link List} representation of the builders content, the actual
     *         implementation is an {@link CopyOnWriteArrayList}
     */
    public List<E> toConcurrentList() {
        return new CopyOnWriteArrayList<>(collector);
    }

    /**
     * @return a concurrent mutable {@link Set} representation of the builders content, the actual
     *         implementation is an {@link CopyOnWriteArraySet}
     */
    public Set<E> toConcurrentSet() {
        return new CopyOnWriteArraySet<>(collector);
    }

    /**
     * @return a mutable {@link NavigableSet} representation of the builders content, the actual
     *         implementation is an {@link TreeSet}. The assumption is that the Actual type is at
     *         least {@link Comparable}
     */
    public NavigableSet<E> toMutableNavigableSet() {
        return new TreeSet<>(collector);
    }

    /**
     * @return an immutable {@link NavigableSet} representation of the builders content, the actual
     *         implementation is an {@link TreeSet} wrapped by
     *         {@link Collections#unmodifiableNavigableSet(NavigableSet)}. The assumption is that
     *         the Actual type is at least {@link Comparable}
     */
    public NavigableSet<E> toImmutableNavigableSet() {
        return Collections.unmodifiableNavigableSet(toMutableNavigableSet());
    }

    /**
     * @return a mutable {@link NavigableSet} representation of the builders content, the actual
     *         implementation is an {@link ConcurrentSkipListSet}. The assumption is that the
     *         actual type is at least {@link Comparable}
     */
    public NavigableSet<E> toConcurrentNavigableSet() {
        return new ConcurrentSkipListSet<>(collector);
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

    @Override
    public boolean equals(Object o) {
        if (o instanceof CollectionBuilder) {
            return collector.equals(((CollectionBuilder<?>) o).collector);
        }
        return false;
    }

    @Override
    public int hashCode() {
        return collector.hashCode();
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this).add("collector", collector).toString();
    }

    /**
     * Creates an Instance of {@link CollectionBuilder} by copying the content of the given source
     *
     * @param source may be null
     * @return the newly created {@link CollectionBuilder}
     */
    public static <E> CollectionBuilder<E> copyFrom(Iterable<? extends E> source) {
        return new CollectionBuilder<>(mutableList(source));
    }

    /**
     * Creates an Instance of {@link CollectionBuilder} by copying the content of the given source
     *
     * @param source may be null
     * @return the newly created {@link CollectionBuilder}
     */
    public static <E> CollectionBuilder<E> copyFrom(Iterator<? extends E> source) {
        return new CollectionBuilder<>(mutableList(source));
    }

    /**
     * Creates an Instance of {@link CollectionBuilder} by copying the content of the given source
     *
     * @param source may be null
     * @return the newly created {@link CollectionBuilder}
     */
    public static <E> CollectionBuilder<E> copyFrom(Collection<? extends E> source) {
        return new CollectionBuilder<>(mutableList(source));
    }

    /**
     * Creates an Instance of {@link CollectionBuilder} by copying the content of the given source
     *
     * @param source may be null
     * @return the newly created {@link CollectionBuilder}
     */
    public static <E> CollectionBuilder<E> copyFrom(Stream<? extends E> source) {
        return new CollectionBuilder<>(mutableList(source));
    }

    /**
     * Creates an Instance of {@link CollectionBuilder} by copying the content of the given source
     *
     * @param source may be null
     * @return the newly created {@link CollectionBuilder}
     */
    @SafeVarargs
    public static <E> CollectionBuilder<E> copyFrom(E... source) {
        return new CollectionBuilder<>(mutableList(source));
    }

    /**
     * Creates an Instance of {@link CollectionBuilder} by copying the content of the given source
     *
     * @param source may be null
     * @return the newly created {@link CollectionBuilder}
     */
    public static <E> CollectionBuilder<E> copyFrom(E source) {
        return new CollectionBuilder<>(mutableList(source));
    }

}
