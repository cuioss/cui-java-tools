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
 * <p>
 * Builder for creating {@link Map}s providing some convenience methods. The class writes
 * everything through into the contained collector. Using the default constructor a newly created
 * {@link HashMap} will be used as collector, but you can pass you own collector as
 * constructor-argument. Of course this should be mutable in order to work.
 * </p>
 * <p>
 * Although not being a {@link Map} itself it provides the same methods with different semantics ->
 * Builder approach.
 * </p>
 * <h3>Standard Usage</h3>
 *
 * <pre>
 * MapBuilder&lt;String, String&gt; builder = new MapBuilder<>();
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
 *    assertEquals(4, MapBuilder.from("key1", 1, "key2", 2, "key3", 3, "key4", 4).size()); *
 * </pre>
 *
 * @author Oliver Wolff
 * @param <K> the type of keys maintained by this map
 * @param <V> the type of mapped values
 *
 */
@EqualsAndHashCode
@ToString
public final class MapBuilder<K, V> {

    private final Map<K, V> collector;

    /**
     * Default Constructor initializing the collector with an {@link HashMap}
     *
     */
    public MapBuilder() {
        this(new HashMap<>());
    }

    /**
     * @param collector to be used for storage. Must not be null
     */
    public MapBuilder(Map<K, V> collector) {
        this.collector = requireNonNull(collector);
    }

    /**
     * @return the number of key-value mappings in this map
     * @see Map#size()
     */
    public int size() {
        return collector.size();
    }

    /**
     * @return true if this map contains no key-value mappings
     * @see Map#isEmpty()
     */
    public boolean isEmpty() {
        return collector.isEmpty();
    }

    /**
     * Returns <tt>true</tt> if this map contains a mapping for the specified
     * key. More formally, returns <tt>true</tt> if and only if
     * this map contains a mapping for a key <tt>k</tt> such that
     * <tt>(key==null ? k==null : key.equals(k))</tt>. (There can be
     * at most one such mapping.)
     *
     * @param key key whose presence in this map is to be tested
     * @return <tt>true</tt> if this map contains a mapping for the specified
     *         key
     * @see Map#containsKey(Object)
     */
    public boolean containsKey(Object key) {
        return collector.containsKey(key);
    }

    /**
     * Returns <tt>true</tt> if this map maps one or more keys to the
     * specified value. More formally, returns <tt>true</tt> if and only if
     * this map contains at least one mapping to a value <tt>v</tt> such that
     * <tt>(value==null ? v==null : value.equals(v))</tt>. This operation
     * will probably require time linear in the map size for most
     * implementations of the <tt>Map</tt> interface.
     *
     * @param value value whose presence in this map is to be tested
     * @return <tt>true</tt> if this map maps one or more keys to the
     *         specified value
     * @see Map#containsValue(Object)
     */
    public boolean containsValue(Object value) {
        return collector.containsValue(value);
    }

    /**
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
     * @param entry to be put, must not {@code null}
     * @return the instance itself in order to use it in a fluent way.
     */
    public MapBuilder<K, V> put(Entry<? extends K, ? extends V> entry) {
        collector.put(entry.getKey(), entry.getValue());
        return this;
    }

    /**
     * @param key to be removed
     * @return the instance itself in order to use it in a fluent way.
     */
    public MapBuilder<K, V> remove(Object key) {
        collector.remove(key);
        return this;
    }

    /**
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
     * @return a mutable {@link Map} representation of the builders content, the actual
     *         implementation is a {@link HashMap}
     */
    public Map<K, V> toMutableMap() {
        return new HashMap<>(collector);
    }

    /**
     * @return an immutable {@link Map} representation of the builders content, the actual
     *         implementation does not create a copy but provides an unmodifiable view using
     *         {@link Collections#unmodifiableMap(Map)}
     */
    public Map<K, V> toImmutableMap() {
        return Collections.unmodifiableMap(collector);
    }

    /**
     * @param <K> the type of keys maintained by this map
     * @param <V> the type of mapped values
     * @param original map used to initialize the contained collector
     * @return an instance of {@link MapBuilder} initialized with a copy of the given Map.
     */
    public static <K, V> MapBuilder<K, V> copyFrom(Map<K, V> original) {
        return new MapBuilder<>(new HashMap<>(original));
    }

    /**
     * Shorthand for creating a {@link MapBuilder} from a given key/value pair
     *
     * @param <K> the type of keys maintained by this map
     * @param <V> the type of mapped values
     * @param k1 key to be added
     * @param v1 value to be added
     * @return an instance of {@link MapBuilder} initialized with the given key/value pair.
     */
    public static <K, V> MapBuilder<K, V> from(K k1, V v1) {
        return new MapBuilder<>(mutableMap(k1, v1));
    }

    /**
     * Shorthand for creating a {@link MapBuilder} from given key/value pairs
     *
     * @param <K> the type of keys maintained by this map
     * @param <V> the type of mapped values
     * @param k1 key to be added
     * @param v1 value to be added
     * @param k2 key to be added
     * @param v2 value to be added
     * @return an instance of {@link MapBuilder} initialized with the given key/value pairs.
     */
    public static <K, V> MapBuilder<K, V> from(K k1, V v1, K k2, V v2) {
        return new MapBuilder<>(mutableMap(k1, v1, k2, v2));
    }

    /**
     * Shorthand for creating a {@link MapBuilder} from given key/value pairs
     *
     * @param <K> the type of keys maintained by this map
     * @param <V> the type of mapped values
     * @param k1 key to be added
     * @param v1 value to be added
     * @param k2 key to be added
     * @param v2 value to be added
     * @param k3 key to be added
     * @param v3 value to be added
     * @return an instance of {@link MapBuilder} initialized with the given key/value pairs.
     */
    public static <K, V> MapBuilder<K, V> from(K k1, V v1, K k2, V v2, K k3, V v3) {
        return new MapBuilder<>(mutableMap(k1, v1, k2, v2, k3, v3));
    }

    /**
     * Shorthand for creating a {@link MapBuilder} from given key/value pairs
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
     * @return an instance of {@link MapBuilder} initialized with the given key/value pairs.
     */
    @SuppressWarnings("squid:S00107") // owolff: Number of parameters match to the use-case
    public static <K, V> MapBuilder<K, V> from(K k1, V v1, K k2, V v2, K k3, V v3, K k4, V v4) {
        return new MapBuilder<>(mutableMap(k1, v1, k2, v2, k3, v3, k4, v4));
    }
}
