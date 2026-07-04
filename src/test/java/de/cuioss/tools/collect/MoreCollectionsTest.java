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

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static de.cuioss.tools.collect.CollectionLiterals.*;
import static de.cuioss.tools.collect.MoreCollections.*;
import static org.junit.jupiter.api.Assertions.*;

class MoreCollectionsTest {

    private static final String MESSAGE = "message";

    @Test
    void shouldDetermineEmptinessForVarags() {
        assertFalse(isEmpty("1"));
        assertFalse(isEmpty("1", "2"));
        assertTrue(isEmpty(Collections.emptyList().toArray()));
        assertTrue(isEmpty((Object[]) null));

        requireNotEmpty("1");
        assertArrayEquals(new Integer[]{0, 1}, requireNotEmpty(Integer.valueOf(0), Integer.valueOf(1)));
        assertThrows(IllegalArgumentException.class, () ->
                requireNotEmpty((Object[]) null));
        assertThrows(IllegalArgumentException.class, () ->
                requireNotEmpty(new Object[0]));
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
        assertThrows(IllegalArgumentException.class, () ->
                requireNotEmpty(emptyIterable));

        assertThrows(IllegalArgumentException.class, () ->
                requireNotEmpty(emptyIterable, MESSAGE));
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
        assertThrows(IllegalArgumentException.class, () ->
                requireNotEmpty(emptyList));

        assertThrows(IllegalArgumentException.class, () ->
                requireNotEmpty(emptyList, MESSAGE));
    }

    @Test
    void shouldDetermineEmptinessForMap() {
        assertFalse(isEmpty(mutableMap("1", "2")));
        assertTrue(isEmpty(mutableMap()));
        assertTrue(isEmpty((Map<?, ?>) null));

        requireNotEmpty(mutableMap("1", "2"));
        requireNotEmpty(mutableMap("1", "2"), MESSAGE);
        Map<Object, Object> emptyMutableMap = mutableMap();
        assertThrows(IllegalArgumentException.class, () ->
                requireNotEmpty(emptyMutableMap));

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
        assertThrows(IllegalArgumentException.class, () ->
                requireNotEmpty(emptyIterator));

        assertThrows(IllegalArgumentException.class, () ->
                requireNotEmpty(emptyIterator, MESSAGE));
    }

    @Test
    void shouldDetermineEmptinessForStream() {
        assertFalse(isEmpty(mutableList("1").stream()));
        assertFalse(isEmpty(Collections.emptyList().stream()));
        assertTrue(isEmpty((Stream<?>) null));

        requireNotEmpty(mutableList("1").stream());
        requireNotEmpty(mutableList("1").stream(), MESSAGE);
        assertThrows(IllegalArgumentException.class, () ->
                requireNotEmpty((Stream<String>) null));
        assertThrows(IllegalArgumentException.class, () ->
                requireNotEmpty((Stream<String>) null, MESSAGE));

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
    void differenceShouldImplementDocumentedEqualsAndHashCodeContract() {
        Map<String, String> left = immutableMap("key", "value", "left", "leftOnly", "differing", "valueLeft");
        Map<String, String> right = immutableMap("key", "value", "right", "rightOnly", "differing", "valueRight");

        MapDifference<String, String> diff = difference(left, right);
        MapDifference<String, String> sameDiff = difference(mutableMap("key", "value", "left", "leftOnly",
                "differing", "valueLeft"), mutableMap("key", "value", "right", "rightOnly", "differing", "valueRight"));
        MapDifference<String, String> otherDiff = difference(left, immutableMap("key", "value"));

        assertEquals(diff, diff);
        assertEquals(diff, sameDiff);
        assertEquals(sameDiff, diff);
        assertEquals(diff.hashCode(), sameDiff.hashCode());
        assertEquals(Arrays.asList(diff.entriesOnlyOnLeft(), diff.entriesOnlyOnRight(), diff.entriesInCommon(),
                diff.entriesDiffering()).hashCode(), diff.hashCode());

        assertNotEquals(diff, otherDiff);
        assertNotEquals(diff, "someString");
        assertNotEquals(null, diff);
    }

    @Test
    void valueDifferenceShouldImplementDocumentedEqualsAndHashCodeContract() {
        var difference = difference(immutableMap("key", "value1"), immutableMap("key", "value2"))
                .entriesDiffering().get("key");
        var sameDifference = difference(immutableMap("key", "value1"), immutableMap("key", "value2"))
                .entriesDiffering().get("key");
        var otherDifference = difference(immutableMap("key", "value1"), immutableMap("key", "value3"))
                .entriesDiffering().get("key");

        assertEquals(difference, difference);
        assertEquals(difference, sameDifference);
        assertEquals(sameDifference, difference);
        assertEquals(difference.hashCode(), sameDifference.hashCode());
        assertEquals(Arrays.asList("value1", "value2").hashCode(), difference.hashCode());

        assertNotEquals(difference, otherDifference);
        assertNotEquals(difference, "someString");
        assertNotEquals(null, difference);
        assertNotNull(difference.toString());
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
