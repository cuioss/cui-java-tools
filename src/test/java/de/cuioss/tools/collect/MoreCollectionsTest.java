package de.cuioss.tools.collect;

import static de.cuioss.tools.collect.CollectionLiterals.immutableMap;
import static de.cuioss.tools.collect.CollectionLiterals.mutableList;
import static de.cuioss.tools.collect.CollectionLiterals.mutableMap;
import static de.cuioss.tools.collect.MoreCollections.containsKey;
import static de.cuioss.tools.collect.MoreCollections.difference;
import static de.cuioss.tools.collect.MoreCollections.isEmpty;
import static de.cuioss.tools.collect.MoreCollections.requireNotEmpty;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

class MoreCollectionsTest {

    private static final String MESSAGE = "message";

    @Test
    void shouldDetermineEmptinessForVarags() {
        assertFalse(isEmpty("1"));
        assertFalse(isEmpty("1", "2"));
        assertTrue(isEmpty(Collections.emptyList().toArray()));
        assertTrue(isEmpty((Object[]) null));

        requireNotEmpty("1");
        requireNotEmpty(Integer.valueOf(0), MESSAGE);
    }

    void shouldDetermineEmptinessForArrays() {
        assertFalse(isEmpty(new byte[] { Byte.MIN_VALUE }));
        assertFalse(isEmpty(new byte[] { Byte.MIN_VALUE, Byte.MAX_VALUE }));
        assertTrue(isEmpty((byte[]) null));
        assertTrue(isEmpty(new byte[0]));
    }

    @Test
    void shouldDetermineEmptinessForIterable() {
        assertFalse(isEmpty((Iterable<?>) mutableList("1")));
        assertFalse(isEmpty((Iterable<?>) mutableList("1", "2")));
        assertTrue(isEmpty((Iterable<?>) Collections.emptyList()));
        assertTrue(isEmpty((Iterable<?>) null));

        requireNotEmpty((Iterable<String>) mutableList("1"));
        requireNotEmpty((Iterable<String>) mutableList("1"), MESSAGE);
        Iterable<String> emptyIterable = Collections.emptyList();
        assertThrows(IllegalArgumentException.class, () -> {
            requireNotEmpty(emptyIterable);
        });

        assertThrows(IllegalArgumentException.class, () -> {
            requireNotEmpty(emptyIterable, MESSAGE);
        });
    }

    @Test
    void shouldDetermineEmptinessForCollection() {
        assertFalse(isEmpty(mutableList("1")));
        assertFalse(isEmpty(mutableList("1", "2")));
        assertTrue(isEmpty(Collections.emptyList()));
        assertTrue(isEmpty((Collection<?>) null));

        requireNotEmpty(mutableList("1"));
        requireNotEmpty(mutableList("1"), MESSAGE);
        List<String> emptyList = Collections.emptyList();
        assertThrows(IllegalArgumentException.class, () -> {
            requireNotEmpty(emptyList);
        });

        assertThrows(IllegalArgumentException.class, () -> {
            requireNotEmpty(emptyList, MESSAGE);
        });
    }

    @Test
    void shouldDetermineEmptinessForMap() {
        assertFalse(isEmpty(mutableMap("1", "2")));
        assertTrue(isEmpty(mutableMap()));
        assertTrue(isEmpty((Map<?, ?>) null));

        requireNotEmpty(mutableMap("1", "2"));
        requireNotEmpty(mutableMap("1", "2"), MESSAGE);
        Map<Object, Object> emptyMutableMap = mutableMap();
        assertThrows(IllegalArgumentException.class, () -> {
            requireNotEmpty(emptyMutableMap);
        });

    }

    @Test
    void shouldDetermineEmptinessForIterator() {
        assertFalse(isEmpty(mutableList("1").iterator()));
        assertFalse(isEmpty(mutableList("1", "2").iterator()));
        assertTrue(isEmpty(Collections.emptyIterator()));
        assertTrue(isEmpty((Iterator<?>) null));

        requireNotEmpty(mutableList("1").iterator());
        requireNotEmpty(mutableList("1").iterator(), MESSAGE);
        Iterator<String> emptyIterator = Collections.emptyIterator();
        assertThrows(IllegalArgumentException.class, () -> {
            requireNotEmpty(emptyIterator);
        });

        assertThrows(IllegalArgumentException.class, () -> {
            requireNotEmpty(emptyIterator, MESSAGE);
        });
    }

    @Test
    void shouldDetermineEmptinessForStream() {
        assertFalse(isEmpty(mutableList("1").stream()));
        assertFalse(isEmpty(Collections.emptyList().stream()));
        assertTrue(isEmpty((Stream<?>) null));

        requireNotEmpty(mutableList("1").stream());
        requireNotEmpty(mutableList("1").stream(), MESSAGE);
        assertThrows(IllegalArgumentException.class, () -> {
            requireNotEmpty((Stream<String>) null);
        });
        assertThrows(IllegalArgumentException.class, () -> {
            requireNotEmpty((Stream<String>) null, MESSAGE);
        });

    }

    @Test
    void shouldHandleMapContainsKey() {
        var key = "key";
        var value = "value";
        Map<String, String> map = immutableMap(key, value);

        assertFalse(containsKey(null, key));
        assertFalse(containsKey(Collections.emptyMap(), key));

        assertFalse(containsKey(map));
        assertFalse(containsKey(map, (Object[]) null));
        assertFalse(containsKey(map, value));

        assertTrue(containsKey(map, key, value));
        assertTrue(containsKey(map, value, key));

        assertFalse(containsKey(map, value));

    }

    @Test
    void differenceMapShouldHandleEmpty() {
        var builder = new MapBuilder<String, String>();
        MapDifference<String, String> diff = difference(builder.toMutableMap(), builder.toMutableMap());
        assertNotNull(diff);
        assertTrue(diff.areEqual());
        assertTrue(diff.entriesDiffering().isEmpty());
        assertTrue(diff.entriesInCommon().isEmpty());
        assertTrue(diff.entriesOnlyOnLeft().isEmpty());
        assertTrue(diff.entriesOnlyOnRight().isEmpty());
    }

    @Test
    void differenceMapShouldHandleEmptyImmutable() {
        var builder = new MapBuilder<String, String>();
        MapDifference<String, String> diff = difference(builder.toImmutableMap(), builder.toImmutableMap());
        assertNotNull(diff);
        assertTrue(diff.areEqual());
        assertTrue(diff.entriesDiffering().isEmpty());
        assertTrue(diff.entriesInCommon().isEmpty());
        assertTrue(diff.entriesOnlyOnLeft().isEmpty());
        assertTrue(diff.entriesOnlyOnRight().isEmpty());
    }

    @Test
    void differenceMapShouldHandleRightOnly() {
        var left = new MapBuilder<String, String>();
        var right = new MapBuilder<String, String>().put("key", "value");
        MapDifference<String, String> diff = difference(left.toImmutableMap(), right.toImmutableMap());
        assertNotNull(diff);
        assertFalse(diff.areEqual());
        assertTrue(diff.entriesDiffering().isEmpty());
        assertTrue(diff.entriesInCommon().isEmpty());
        assertTrue(diff.entriesOnlyOnLeft().isEmpty());
        assertFalse(diff.entriesOnlyOnRight().isEmpty());
    }

    @Test
    void differenceMapShouldHandleLeftOnly() {
        var left = new MapBuilder<String, String>().put("key", "value");
        var right = new MapBuilder<String, String>();
        MapDifference<String, String> diff = difference(left.toImmutableMap(), right.toImmutableMap());
        assertNotNull(diff);
        assertFalse(diff.areEqual());
        assertTrue(diff.entriesDiffering().isEmpty());
        assertTrue(diff.entriesInCommon().isEmpty());
        assertFalse(diff.entriesOnlyOnLeft().isEmpty());
        assertTrue(diff.entriesOnlyOnRight().isEmpty());
    }

    @Test
    void differenceMapShouldHandleEqualMap() {
        var left = new MapBuilder<String, String>().put("key", "value");
        MapDifference<String, String> diff = difference(left.toImmutableMap(), left.toImmutableMap());
        assertNotNull(diff);
        assertTrue(diff.areEqual());
        assertTrue(diff.entriesDiffering().isEmpty());
        assertFalse(diff.entriesInCommon().isEmpty());
        assertTrue(diff.entriesOnlyOnLeft().isEmpty());
        assertTrue(diff.entriesOnlyOnRight().isEmpty());
    }

    @Test
    void differenceMapShouldHandlevalueDifference() {
        var left = new MapBuilder<String, String>().put("key", "value");
        var right = new MapBuilder<String, String>().put("key", "value2");
        MapDifference<String, String> diff = difference(left.toImmutableMap(), right.toImmutableMap());
        assertNotNull(diff);
        assertFalse(diff.areEqual());
        assertFalse(diff.entriesDiffering().isEmpty());
        assertTrue(diff.entriesInCommon().isEmpty());
        assertTrue(diff.entriesOnlyOnLeft().isEmpty());
        assertTrue(diff.entriesOnlyOnRight().isEmpty());
    }

    @Test
    void differenceMapShouldHandleEntrieWithNull() {
        var left = new MapBuilder<String, String>().put("key", "value").put("key2", null);
        var right = new MapBuilder<String, String>().put("key", null).put("key2", "value");
        MapDifference<String, String> diff = difference(left.toImmutableMap(), right.toImmutableMap());
        assertNotNull(diff);
        assertFalse(diff.areEqual());
        assertEquals(2, diff.entriesDiffering().size());
        assertNull(diff.entriesDiffering().get("key").rightValue());
        assertEquals("value", diff.entriesDiffering().get("key").leftValue());
        assertNull(diff.entriesDiffering().get("key2").leftValue());
        assertEquals("value", diff.entriesDiffering().get("key2").rightValue());
        assertTrue(diff.entriesInCommon().isEmpty());
        assertTrue(diff.entriesOnlyOnLeft().isEmpty());
        assertTrue(diff.entriesOnlyOnRight().isEmpty());
    }
}
