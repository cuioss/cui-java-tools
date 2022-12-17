package io.cui.util.collect;

import static io.cui.util.collect.CollectionLiterals.mutableList;
import static java.util.Objects.requireNonNull;

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

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

/**
 * Builder for creating {@link Collection}s providing some convenience methods. The class writes
 * everything through into the contained collector. Using the default constructor a newly created
 * {@link ArrayList} will be used as collector, but you can pass you own collector as
 * constructor-argument. Of course this should be mutable in order to work.
 * <h3>Handling of null-values</h3>
 * <p>
 * As default {@code null} values are ignored. This behavior can be changed by call
 * {@link #addNullValues(boolean)}.
 * <em>Caution:</em> In case of using one of the {@link #copyFrom(Collection)}
 * methods for instantiation the {@code null} values will not be checked in that way
 * <p>
 * <h3>Standard Usage</h3>
 *
 * <pre>
 *
 * List&lt;String&gt; result = new CollectionBuilder&lt;String&gt;().add("this").add("that")
 *         .add(mutableList("on", "or an other")).toImmutableList();
 * </pre>
 *
 * or
 *
 * <pre>
 *
 * Set&lt;String&gt; result = new CollectionBuilder&lt;String&gt;().add("this").add("that")
 *         .add(mutableList("on", "or an other")).toMutableSet();
 * </pre>
 *
 * <h3>Copy From</h3>
 * This methods can be used for ensuring a real copy
 *
 * <pre>
 *
 * List&lt;String&gt; result =
 *     CollectionBuilder.copyFrom(mutableList("on", "or an other")).add("element").toMutableList();
 *
 * </pre>
 *
 * <h3>Sorting</h3>
 * <p>
 * The contained {@link Collection} can be sorted any time by calling {@link #sort(Comparator)}
 * </p>
 *
 * @author Oliver Wolff
 * @param <E> The type of the contained {@link Collection}
 *
 */
@EqualsAndHashCode
@ToString
public final class CollectionBuilder<E> implements Iterable<E> {

    private final Collection<E> collector;

    /**
     * If set to {@code true} {@code null} elements are added to the contained collector, if
     * {@code false}, default value, {@code null} values are ignored.
     */
    @Getter
    private boolean addNullValues = false;

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
     * @param addNullValues If set to {@code true} {@code null} elements are added to the contained
     *            collector, if {@code false}, default value, {@code null} values are ignored.
     * @return the instance itself in order to use it in a fluent way.
     */
    public CollectionBuilder<E> addNullValues(boolean addNullValues) {
        this.addNullValues = addNullValues;
        return this;
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

    public Stream<E> stream() {
        return collector.stream();
    }

    /**
     * @param e the element to be added
     * @return the instance itself in order to use it in a fluent way. <em>Caution:</em> with this
     *         call the return value of {@link Collection#add(Object)} will be ignored.
     */
    public CollectionBuilder<E> add(E e) {
        if (addNullValues || null != e) {
            collector.add(e);
        }
        return this;
    }

    /**
     * @param elements to be added
     * @return the instance itself in order to use it in a fluent way. <em>Caution:</em> with this
     *         call the return value of {@link Collection#add(Object)} will be ignored.
     */
    public CollectionBuilder<E> add(@SuppressWarnings("unchecked") E... elements) {
        if (!MoreCollections.isEmpty(elements)) {
            for (E element : elements) {
                add(element);
            }
        }
        return this;
    }

    /**
     * @param elements to be added
     * @return the instance itself in order to use it in a fluent way. <em>Caution:</em> with this
     *         call the return value of {@link Collection#add(Object)} will be ignored.
     */
    public CollectionBuilder<E> add(Iterable<E> elements) {
        if (!MoreCollections.isEmpty(elements)) {
            elements.forEach(this::add);
        }
        return this;
    }

    /**
     * @param elements to be added
     * @return the instance itself in order to use it in a fluent way. <em>Caution:</em> with this
     *         call the return value of {@link Collection#add(Object)} will be ignored.
     */
    public CollectionBuilder<E> add(Collection<E> elements) {
        if (!MoreCollections.isEmpty(elements)) {
            elements.forEach(this::add);
        }
        return this;
    }

    /**
     * @param element to be added if present.
     *            <em>Caution</em>: passing an {@link Optional}
     *            parameter is a not a good thing to do, I know, but in this context it is quite
     *            convenient: Don't do this at home
     * @return the instance itself in order to use it in a fluent way. <em>Caution:</em> with this
     *         call the return value of {@link Collection#add(Object)} will be ignored.
     */
    public CollectionBuilder<E> add(Optional<E> element) {
        element.ifPresent(this::add);
        return this;
    }

    /**
     * @param elements to be added
     * @return the instance itself in order to use it in a fluent way. <em>Caution:</em> with this
     *         call the return value of {@link Collection#add(Object)} will be ignored.
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
     * @param targetType identifying the concrete ArrayType
     * @return an array representation of the builders content
     */
    @SuppressWarnings("unchecked")
    public E[] toArray(Class<? super E> targetType) {
        if (isEmpty()) {
            return (E[]) Array.newInstance(targetType, 0);
        }
        E[] target = (E[]) Array.newInstance(targetType, size());
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
     * Creates an Instance of {@link CollectionBuilder} by copying the content of the given source
     * <em>Caution:</em> The given source will be used as it is, there will be no filtering as
     * defined within {@link #addNullValues(boolean)}
     *
     * @param source may be null
     * @return the newly created {@link CollectionBuilder}
     */
    public static <E> CollectionBuilder<E> copyFrom(Iterable<? extends E> source) {
        return new CollectionBuilder<>(mutableList(source));
    }

    /**
     * Creates an Instance of {@link CollectionBuilder} by copying the content of the given source
     * <em>Caution:</em> The given source will be used as it is, there will be no filtering as
     * defined within {@link #addNullValues(boolean)}
     *
     * @param source may be null
     * @return the newly created {@link CollectionBuilder}
     */
    public static <E> CollectionBuilder<E> copyFrom(Iterator<? extends E> source) {
        return new CollectionBuilder<>(mutableList(source));
    }

    /**
     * Creates an Instance of {@link CollectionBuilder} by copying the content of the given source
     * <em>Caution:</em> The given source will be used as it is, there will be no filtering as
     * defined within {@link #addNullValues(boolean)}
     *
     * @param source may be null
     * @return the newly created {@link CollectionBuilder}
     */
    public static <E> CollectionBuilder<E> copyFrom(Collection<? extends E> source) {
        return new CollectionBuilder<>(mutableList(source));
    }

    /**
     * Creates an Instance of {@link CollectionBuilder} by copying the content of the given source
     * <em>Caution:</em> The given source will be used as it is, there will be no filtering as
     * defined within {@link #addNullValues(boolean)}
     *
     * @param source may be null
     * @return the newly created {@link CollectionBuilder}
     */
    public static <E> CollectionBuilder<E> copyFrom(Stream<? extends E> source) {
        return new CollectionBuilder<>(mutableList(source));
    }

    /**
     * Creates an Instance of {@link CollectionBuilder} by copying the content of the given source
     * <em>Caution:</em> The given source will be used as it is, there will be no filtering as
     * defined within {@link #addNullValues(boolean)}
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
     * <em>Caution:</em> The given source will be used as it is, there will be no filtering as
     * defined within {@link #addNullValues(boolean)}
     *
     * @param source may be null
     * @return the newly created {@link CollectionBuilder}
     */
    public static <E> CollectionBuilder<E> copyFrom(E source) {
        return new CollectionBuilder<>(mutableList(source));
    }

}
