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

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import java.util.stream.Stream;

import static de.cuioss.tools.collect.CollectionLiterals.*;
import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Collection Literals Test Suite")
@EnableGeneratorController
class CollectionLiteralsTest {

    @Test
    @DisplayName("Should handle edge cases for mutable list with collections")
    void shouldHandleMutableListEdgeCases() {
        // Test with empty collection
        var emptyList = mutableList(new ArrayList<String>());
        assertTrue(emptyList.isEmpty());
        var testString = Generators.nonEmptyStrings().next();
        emptyList.add(testString);
        assertEquals(1, emptyList.size());

        // Test with null elements in collection
        var value = Generators.nonEmptyStrings().next();
        var listWithNulls = mutableList(Arrays.asList(null, value, null));
        assertEquals(3, listWithNulls.size());
        assertNull(listWithNulls.getFirst());
        assertEquals(value, listWithNulls.get(1));
    }

    @Test
    @DisplayName("Should maintain order in mutable lists")
    void shouldMaintainOrderInLists() {
        var first = Generators.nonEmptyStrings().next();
        var second = Generators.nonEmptyStrings().next();
        var third = Generators.nonEmptyStrings().next();
        
        var list = mutableList(first, second, third);
        assertEquals(first, list.getFirst());
        assertEquals(second, list.get(1));
        assertEquals(third, list.get(2));

        // Verify it's truly mutable
        var modified = Generators.nonEmptyStrings().next();
        list.set(1, modified);
        assertEquals(modified, list.get(1));
    }

    @Test
    @DisplayName("Should handle duplicate elements in sets")
    void shouldHandleDuplicatesInSets() {
        var a = Generators.letterStrings(1, 5).next();
        var b = Generators.letterStrings(1, 5).next();
        var c = Generators.letterStrings(1, 5).next();
        
        var set = mutableSet(a, b, a, c, b);
        // Size depends on whether generated strings are equal
        assertTrue(set.size() <= 3); // Duplicates removed
        assertTrue(set.contains(a));
        assertTrue(set.contains(b));
        assertTrue(set.contains(c));
    }

    @Test
    @DisplayName("Should properly sort elements in sorted sets")
    void shouldSortElementsInSortedSet() {
        var sortedSet = mutableSortedSet("zebra", "apple", "mango", "banana");
        var iterator = sortedSet.iterator();
        assertEquals("apple", iterator.next());
        assertEquals("banana", iterator.next());
        assertEquals("mango", iterator.next());
        assertEquals("zebra", iterator.next());
    }

    @Test
    @DisplayName("Should create map with maximum 4 key-value pairs")
    void shouldCreateMapWithMultiplePairs() {
        var map = mutableMap("k1", "v1", "k2", "v2", "k3", "v3", "k4", "v4");
        assertEquals(4, map.size());
        assertEquals("v1", map.get("k1"));
        assertEquals("v2", map.get("k2"));
        assertEquals("v3", map.get("k3"));
        assertEquals("v4", map.get("k4"));

        // Verify it's mutable
        map.put("k5", "v5");
        assertEquals(5, map.size());
    }

    @Test
    @DisplayName("Should preserve null values in maps")
    void shouldPreserveNullValuesInMaps() {
        var map = mutableMap("key1", null, "key2", "value2");
        assertTrue(map.containsKey("key1"));
        assertNull(map.get("key1"));
        assertEquals("value2", map.get("key2"));
    }

    @Nested
    @DisplayName("List Operations")
    class ListTests {
        @Test
        @DisplayName("Should handle mutable list operations")
        void shouldHandleMutableList() {
            assertMutable(mutableList());
            assertMutable(mutableList((String[]) null));
            assertMutable(mutableList((String) null));
            assertMutable(mutableList("1"));
            assertMutable(mutableList("1", "2"));
            assertMutable(mutableList(new ArrayList<>()));
            assertMutable(mutableList(Arrays.asList("1", "2")));
            assertMutable(mutableList((Iterable<String>) null));
            assertMutable(mutableList((Iterable<String>) Arrays.asList("1", "2")));
            assertMutable(mutableList((Iterator<String>) null));
            assertMutable(mutableList(Arrays.asList("1", "2").iterator()));
            assertMutable(mutableList((Stream<String>) null));
            assertMutable(mutableList(Arrays.asList("1", "2").stream()));
        }

        @Test
        @DisplayName("Should handle immutable list operations")
        void shouldHandleImmutableList() {
            assertImmutable(immutableList());
            assertImmutable(immutableList((String[]) null));
            assertImmutable(immutableList((String) null));
            assertImmutable(immutableList("1"));
            assertImmutable(immutableList("1", "2"));
            assertImmutable(immutableList(new ArrayList<>()));
            assertImmutable(immutableList((Iterable<String>) null));
            assertImmutable(immutableList(Arrays.asList("1", "2")));
            assertImmutable(immutableList(mutableSet("1", "2")));
            assertImmutable(immutableList((Iterable<String>) Arrays.asList("1", "2")));
            assertImmutable(immutableList((Iterator<String>) null));
            assertImmutable(immutableList(Arrays.asList("1", "2").iterator()));
            assertImmutable(immutableList((Stream<String>) null));
            assertImmutable(immutableList(Arrays.asList("1", "2").stream()));
        }
    }

    @Nested
    @DisplayName("Set Operations")
    class SetTests {
        @Test
        @DisplayName("Should handle mutable set operations")
        void shouldHandleMutableSet() {
            assertMutable(mutableSet());
            assertMutable(mutableSet((String[]) null));
            assertMutable(mutableSet((String) null));
            assertMutable(mutableSet("1"));
            assertMutable(mutableSet("1", "2"));
            assertMutable(mutableSet(new ArrayList<>()));
            assertMutable(mutableSet(Arrays.asList("1", "2")));
            assertMutable(mutableSet((Iterable<String>) null));
            assertMutable(mutableSet((Iterable<String>) Arrays.asList("1", "2")));
            assertMutable(mutableSet((Iterator<String>) null));
            assertMutable(mutableSet(Arrays.asList("1", "2").iterator()));
            assertMutable(mutableSet((Stream<String>) null));
            assertMutable(mutableSet(Arrays.asList("1", "2").stream()));
        }

        @Test
        @DisplayName("Should handle immutable set operations")
        void shouldHandleImmutableSet() {
            assertImmutable(immutableSet());
            assertImmutable(immutableSet((String[]) null));
            assertImmutable(immutableSet((String) null));
            assertImmutable(immutableSet("1"));
            assertImmutable(immutableSet("1", "2"));
            assertImmutable(immutableSet(Arrays.asList("1", "2")));
            assertImmutable(immutableSet((Iterable<String>) null));
            assertImmutable(immutableSet(Arrays.asList("1", "2")));
            assertImmutable(immutableSet((Iterator<String>) null));
            assertImmutable(immutableSet(Arrays.asList("1", "2").iterator()));
            assertImmutable(immutableSet((Stream<String>) null));
            assertImmutable(immutableSet(Arrays.asList("1", "2").stream()));
        }

        @Test
        @DisplayName("Should handle mutable sorted set operations")
        void shouldHandleMutableSortedSet() {
            assertMutable(mutableSortedSet());
            assertMutable(mutableSortedSet((String[]) null));
            assertMutable(mutableSortedSet((String) null));
            assertMutable(mutableSortedSet("1"));
            assertMutable(mutableSortedSet("1", "2"));
            assertMutable(mutableSortedSet((Iterable<String>) null));
            assertMutable(mutableSortedSet(Arrays.asList("1", "2")));
            assertMutable(mutableSortedSet(Arrays.asList("1", "2")));
            assertMutable(mutableSortedSet((Iterator<String>) null));
            assertMutable(mutableSortedSet(Arrays.asList("1", "2").iterator()));
            assertMutable(mutableSortedSet((Stream<String>) null));
            assertMutable(mutableSortedSet(Arrays.asList("1", "2").stream()));
        }

        @Test
        @DisplayName("Should handle immutable sorted set operations")
        void shouldHandleImmutableSortedSet() {
            assertImmutable(immutableSortedSet());
            assertImmutable(immutableSortedSet((String[]) null));
            assertImmutable(immutableSortedSet((String) null));
            assertImmutable(immutableSortedSet("1"));
            assertImmutable(immutableSortedSet("1", "2"));
            assertImmutable(immutableSortedSet((Iterable<String>) null));
            assertImmutable(immutableSortedSet(Arrays.asList("1", "2")));
            assertImmutable(immutableSortedSet((Iterator<String>) null));
            assertImmutable(immutableSortedSet(Arrays.asList("1", "2").iterator()));
            assertImmutable(immutableSortedSet((Stream<String>) null));
            assertImmutable(immutableSortedSet(Arrays.asList("1", "2").stream()));
        }
    }

    @Nested
    @DisplayName("Map Operations")
    class MapTests {
        @Test
        @DisplayName("Should handle mutable map operations")
        void shouldHandleMutableMap() {
            assertMutable(mutableMap());
            assertMutable(mutableMap("1", "1-1"));
            assertMutable(mutableMap("1", "1-1", "2", "2-2"));
            assertMutable(mutableMap("1", "1-1", "2", "2-2", "3", "3-3"));
            assertMutable(mutableMap("1", "1-1", "2", "2-2", "3", "3-3", "4", "4-4"));
        }

        @Test
        @DisplayName("Should handle immutable map operations")
        void shouldHandleImmutableMap() {
            assertImmutable(immutableMap());
            assertImmutable(immutableMap(mutableMap("1", "2")));
            assertImmutable(immutableMap("1", "2"));
            assertImmutable(immutableMap("1", "1-1", "2", "2-2"));
            assertImmutable(immutableMap("1", "1-1", "2", "2-2", "3", "3-3"));
            assertImmutable(immutableMap("1", "1-1", "2", "2-2", "3", "3-3", "4", "4-4"));
        }

        @Test
        @DisplayName("Should handle stream to immutable map conversion")
        void shouldHandleStreamToImmutableMap() {
            final Map<String, String> result = immutableMap(
                    immutableMap("1", "1-1", "2", "").entrySet().stream().filter(entry -> !"".equals(entry.getValue())));
            assertEquals(1, result.size());
            assertTrue(result.containsKey("1"));
        }
    }

    static void assertMutable(Collection<String> collection) {
        assertNotNull(collection);
        collection.add("I am mutable");
    }

    static void assertImmutable(Collection<String> collection) {
        assertNotNull(collection);
        assertThrows(UnsupportedOperationException.class, () ->
                collection.add("i am not mutable"));
    }

    static void assertMutable(Map<String, String> map) {
        assertNotNull(map);
        map.put("I am", "mutable");
    }

    static void assertImmutable(Map<String, String> map) {
        assertNotNull(map);
        assertThrows(UnsupportedOperationException.class, () ->
                map.put("i am", "not mutable"));
    }
}
