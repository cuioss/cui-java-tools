package io.cui.tools.collect;

import static java.util.Objects.requireNonNull;

import java.util.Map;
import java.util.Map.Entry;

import io.cui.tools.collect.MapDifference.ValueDifference;
import lombok.EqualsAndHashCode;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

/**
 * @author Oliver Wolff
 *
 */
@RequiredArgsConstructor
@EqualsAndHashCode
@ToString
class MapDiffenceImpl<K, V> implements MapDifference<K, V> {

    private final Map<K, V> entriesOnlyOnRight;
    private final Map<K, V> entriesOnlyOnLeft;
    private final Map<K, V> entriesInCommon;
    private final Map<K, ValueDifference<V>> entriesDiffering;

    @Override
    public boolean areEqual() {
        return entriesOnlyOnLeft.isEmpty() && entriesOnlyOnRight.isEmpty() && entriesDiffering.isEmpty();
    }

    @Override
    public Map<K, V> entriesOnlyOnLeft() {
        return entriesOnlyOnLeft;
    }

    @Override
    public Map<K, V> entriesOnlyOnRight() {
        return entriesOnlyOnRight;
    }

    @Override
    public Map<K, V> entriesInCommon() {
        return entriesInCommon;
    }

    @Override
    public Map<K, ValueDifference<V>> entriesDiffering() {
        return entriesDiffering;
    }

    /**
     * Computes the difference between two maps. This difference is an immutable snapshot of the
     * state of the maps at the time this method is called. It will never change, even if the maps
     * change at a later time.
     *
     * <p>
     * Since this method uses {@code HashMap} instances internally, the keys of the supplied maps
     * must be well-behaved with respect to {@link Object#equals} and {@link Object#hashCode}.
     *
     * <p>
     * <b>Note:</b>If you only need to know whether two maps have the same mappings, call {@code
     * left.equals(right)} instead of this method.
     *
     * @param left the map to treat as the "left" map for purposes of comparison
     * @param right the map to treat as the "right" map for purposes of comparison
     * @return the difference between the two maps
     *
     * @author com.google.common.collect.MapDifference<K, V>
     */
    static <K, V> MapDifference<K, V> from(
            Map<? extends K, ? extends V> left, Map<? extends K, ? extends V> right) {
        requireNonNull(left);
        requireNonNull(right);

        MapBuilder<K, V> onlyRight = new MapBuilder<>();
        MapBuilder<K, V> onlyLeft = new MapBuilder<>();
        MapBuilder<K, V> common = new MapBuilder<>();
        MapBuilder<K, ValueDifference<V>> entriesDiffering = new MapBuilder<>();

        sortEntriesToBucket(left, right, onlyLeft, common, entriesDiffering);
        // now from the other direction.
        sortEntriesToBucket(right, left, onlyRight, common, entriesDiffering);
        return new MapDiffenceImpl<>(onlyRight.toImmutableMap(), onlyLeft.toImmutableMap(), common.toImmutableMap(),
                entriesDiffering.toImmutableMap());
    }

    static <V, K> void sortEntriesToBucket(Map<? extends K, ? extends V> left, Map<? extends K, ? extends V> right,
            MapBuilder<K, V> onlyLeft, MapBuilder<K, V> common, MapBuilder<K, ValueDifference<V>> entriesDiffering) {
        for (Entry<? extends K, ? extends V> entry : left.entrySet()) {
            if (right.containsKey(entry.getKey())) {
                V rightValue = right.get(entry.getKey());
                V leftValue = entry.getValue();
                if (checkEqualityNullsafe(leftValue, rightValue)) {
                    // Ensure not adding again for the second run
                    if (!common.containsKey(entry.getKey())) {
                        common.put(entry);
                    }
                    // Ensure not adding again for the second run
                } else if (!entriesDiffering.containsKey(entry.getKey())) {
                    entriesDiffering.put(entry.getKey(), new ValueDifferenceImpl<>(leftValue, rightValue));
                }
            } else {
                onlyLeft.put(entry);
            }
        }
    }

    private static boolean checkEqualityNullsafe(Object leftValue, Object rightValue) {
        if (leftValue == rightValue) {
            return true;
        }
        if (null == leftValue || null == rightValue) {
            return false;
        }
        return leftValue.equals(rightValue);
    }
}

@RequiredArgsConstructor
class ValueDifferenceImpl<V> implements ValueDifference<V> {

    private final V leftValue;

    /** Returns the value from the right map (possibly null). */
    private final V rightValue;

    @Override
    public V leftValue() {
        return leftValue;
    }

    @Override
    public V rightValue() {
        return rightValue;
    }
}