package io.cui.tools.collect;

import static io.cui.tools.collect.CollectionLiterals.mutableMap;
import static java.util.Objects.requireNonNull;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import lombok.EqualsAndHashCode;
import lombok.ToString;

/**
 * <h2>Overview</h2>
 * <p>
 * Builder for creating {@link java.util.Map}s providing some convenience methods. The class writes
 * everything through into the contained collector. Using the default constructor a newly created
 * {@link java.util.HashMap} will be used as collector, but you can pass you own collector as
 * constructor-argument. Of course this should be mutable in order to work.
 * </p>
 * <p>
 * Although not being a {@link java.util.Map} itself it provides the same methods with different
 * semantics -&gt; Builder approach.
 * </p>
 * <h3>Standard Usage</h3>
 *
 * <pre>
 * MapBuilder&lt;String, String&gt; builder = new MapBuilder&lt;&gt;();
 * builder.put("key1", "value1").put("key2", "value2");
 * assertEquals(2, builder.size());
 * assertMutable(builder.toMutableMap());
 * assertImmutable(builder.toImmutableMap());
 * </pre>
 *
 * <h3>Using from()</h3>
 * This methods can be used for ensuring a real copy
 *
 * <pre>
 * assertEquals(4, MapBuilder.from("key1", 1, "key2", 2, "key3", 3, "key4", 4).size());
 * </pre>
 *
 * @author Oliver Wolff
 * @param <K> the type of keys maintained by this map
 * @param <V> the type of mapped values
 */
@EqualsAndHashCode
@ToString
public final class MapBuilder<K, V> {

    private final Map<K, V> collector;

    /**
     * Default Constructor initializing the collector with an {@link java.util.HashMap}
     */
    public MapBuilder() {
        this(new HashMap<>());
    }

    /**
     * <p>
     * Constructor for MapBuilder.
     * </p>
     *
     * @param collector to be used for storage. Must not be null
     */
    public MapBuilder(Map<K, V> collector) {
        this.collector = requireNonNull(collector);
    }

    /**
     * <p>
     * size.
     * </p>
     *
     * @return the number of key-value mappings in this map
     * @see Map#size()
     */
    public int size() {
        return collector.size();
    }

    /**
     * <p>
     * isEmpty.
     * </p>
     *
     * @return true if this map contains no key-value mappings
     * @see Map#isEmpty()
     */
    public boolean isEmpty() {
        return collector.isEmpty();
    }

    /**
     * Returns {@code true} if this map contains a mapping for the specified
     * key. More formally, returns {@code true} if and only if
     * this map contains a mapping for a key {@code k} such that
     * {@code (key==null ? k==null : key.equals(k))}. (There can be
     * at most one such mapping.)
     *
     * @param key key whose presence in this map is to be tested
     * @return {@code true} if this map contains a mapping for the specified
     *         key
     * @see Map#containsKey(Object)
     */
    public boolean containsKey(Object key) {
        return collector.containsKey(key);
    }

    /**
     * Returns {@code true} if this map maps one or more keys to the
     * specified value. More formally, returns {@code true} if and only if
     * this map contains at least one mapping to a value {@code v} such that
     * {@code (value==null ? v==null : value.equals(v))}. This operation
     * will probably require time linear in the map size for most
     * implementations of the {@code Map} interface.
     *
     * @param value value whose presence in this map is to be tested
     * @return {@code true} if this map maps one or more keys to the
     *         specified value
     * @see Map#containsValue(Object)
     */
    public boolean containsValue(Object value) {
        return collector.containsValue(value);
    }

    /**
     * <p>
     * put.
     * </p>
     *
     * @param key to be put as key, must not be empty
     * @param value to be put as value, must not be empty
     * @return the instance itself in order to use it in a fluent way.
     */
    public MapBuilder<K, V> put(K key, V value) {
        collector.put(key, value);
        return this;
    }

    /**
     * Puts the entry into the map, if the value is not {@code null}.
     *
     * @param key to be put as key, must not be empty
     * @param value to be put as value
     * @return the instance itself in order to use it in a fluent way.
     */
    public MapBuilder<K, V> putIfNotNull(K key, V value) {
        if (null != value) {
            collector.put(key, value);
        }
        return this;
    }

    /**
     * <p>
     * put.
     * </p>
     *
     * @param entry to be put, must not {@code null}
     * @return the instance itself in order to use it in a fluent way.
     */
    public MapBuilder<K, V> put(Entry<? extends K, ? extends V> entry) {
        collector.put(entry.getKey(), entry.getValue());
        return this;
    }

    /**
     * <p>
     * remove.
     * </p>
     *
     * @param key to be removed
     * @return the instance itself in order to use it in a fluent way.
     */
    public MapBuilder<K, V> remove(Object key) {
        collector.remove(key);
        return this;
    }

    /**
     * <p>
     * putAll.
     * </p>
     *
     * @param map to be put
     * @return the instance itself in order to use it in a fluent way.
     */
    public MapBuilder<K, V> putAll(Map<? extends K, ? extends V> map) {
        collector.putAll(map);
        return this;
    }

    /**
     * Clears the contained collector
     *
     * @return the instance itself in order to use it in a fluent way.
     */
    public MapBuilder<K, V> clear() {
        collector.clear();
        return this;
    }

    /**
     * <p>
     * toMutableMap.
     * </p>
     *
     * @return a mutable {@link java.util.Map} representation of the builders content, the actual
     *         implementation is a {@link java.util.HashMap}
     */
    public Map<K, V> toMutableMap() {
        return new HashMap<>(collector);
    }

    /**
     * <p>
     * toImmutableMap.
     * </p>
     *
     * @return an immutable {@link java.util.Map} representation of the builders content, the actual
     *         implementation does not create a copy but provides an unmodifiable view using
     *         {@link java.util.Collections#unmodifiableMap(Map)}
     */
    public Map<K, V> toImmutableMap() {
        return Collections.unmodifiableMap(collector);
    }

    /**
     * <p>
     * copyFrom.
     * </p>
     *
     * @param <K> the type of keys maintained by this map
     * @param <V> the type of mapped values
     * @param original map used to initialize the contained collector
     * @return an instance of {@link io.cui.tools.collect.MapBuilder} initialized with a copy of the
     *         given Map.
     */
    public static <K, V> MapBuilder<K, V> copyFrom(Map<K, V> original) {
        return new MapBuilder<>(new HashMap<>(original));
    }

    /**
     * Shorthand for creating a {@link io.cui.tools.collect.MapBuilder} from a given key/value pair
     *
     * @param <K> the type of keys maintained by this map
     * @param <V> the type of mapped values
     * @param k1 key to be added
     * @param v1 value to be added
     * @return an instance of {@link io.cui.tools.collect.MapBuilder} initialized with the given
     *         key/value pair.
     */
    public static <K, V> MapBuilder<K, V> from(K k1, V v1) {
        return new MapBuilder<>(mutableMap(k1, v1));
    }

    /**
     * Shorthand for creating a {@link io.cui.tools.collect.MapBuilder} from given key/value pairs
     *
     * @param <K> the type of keys maintained by this map
     * @param <V> the type of mapped values
     * @param k1 key to be added
     * @param v1 value to be added
     * @param k2 key to be added
     * @param v2 value to be added
     * @return an instance of {@link io.cui.tools.collect.MapBuilder} initialized with the given
     *         key/value pairs.
     */
    public static <K, V> MapBuilder<K, V> from(K k1, V v1, K k2, V v2) {
        return new MapBuilder<>(mutableMap(k1, v1, k2, v2));
    }

    /**
     * Shorthand for creating a {@link io.cui.tools.collect.MapBuilder} from given key/value pairs
     *
     * @param <K> the type of keys maintained by this map
     * @param <V> the type of mapped values
     * @param k1 key to be added
     * @param v1 value to be added
     * @param k2 key to be added
     * @param v2 value to be added
     * @param k3 key to be added
     * @param v3 value to be added
     * @return an instance of {@link io.cui.tools.collect.MapBuilder} initialized with the given
     *         key/value pairs.
     */
    public static <K, V> MapBuilder<K, V> from(K k1, V v1, K k2, V v2, K k3, V v3) {
        return new MapBuilder<>(mutableMap(k1, v1, k2, v2, k3, v3));
    }

    /**
     * Shorthand for creating a {@link io.cui.tools.collect.MapBuilder} from given key/value pairs
     *
     * @param <K> the type of keys maintained by this map
     * @param <V> the type of mapped values
     * @param k1 key to be added
     * @param v1 value to be added
     * @param k2 key to be added
     * @param v2 value to be added
     * @param k3 key to be added
     * @param v3 value to be added
     * @param k4 key to be added
     * @param v4 value to be added
     * @return an instance of {@link io.cui.tools.collect.MapBuilder} initialized with the given
     *         key/value pairs.
     */
    @SuppressWarnings("squid:S00107") // owolff: Number of parameters match to the use-case
    public static <K, V> MapBuilder<K, V> from(K k1, V v1, K k2, V v2, K k3, V v3, K k4, V v4) {
        return new MapBuilder<>(mutableMap(k1, v1, k2, v2, k3, v3, k4, v4));
    }
}
