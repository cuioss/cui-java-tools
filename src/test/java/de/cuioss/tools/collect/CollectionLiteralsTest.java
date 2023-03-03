package de.cuioss.tools.collect;

import static de.cuioss.tools.collect.CollectionLiterals.immutableList;
import static de.cuioss.tools.collect.CollectionLiterals.immutableMap;
import static de.cuioss.tools.collect.CollectionLiterals.immutableSet;
import static de.cuioss.tools.collect.CollectionLiterals.immutableSortedSet;
import static de.cuioss.tools.collect.CollectionLiterals.mutableList;
import static de.cuioss.tools.collect.CollectionLiterals.mutableMap;
import static de.cuioss.tools.collect.CollectionLiterals.mutableSet;
import static de.cuioss.tools.collect.CollectionLiterals.mutableSortedSet;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

class CollectionLiteralsTest {

    @Test
    void shouldHandleMutableList() {
        assertMutable(mutableList());
        assertMutable(mutableList((String[]) null));
        assertMutable(mutableList((String) null));
        assertMutable(mutableList("1"));
        assertMutable(mutableList("1", "2"));
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

    @Test
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

    @Test
    void shouldHandleMutableMap() {
        assertMutable(mutableMap());
        assertMutable(mutableMap("1", "1-1"));
        assertMutable(mutableMap("1", "1-1", "2", "2-2"));
        assertMutable(mutableMap("1", "1-1", "2", "2-2", "3", "3-3"));
        assertMutable(mutableMap("1", "1-1", "2", "2-2", "3", "3-3", "4", "4-4"));
    }

    @Test
    void shouldHandleImmutableMap() {
        assertImmutable(immutableMap());
        assertImmutable(immutableMap(mutableMap("1", "2")));
        assertImmutable(immutableMap("1", "2"));
        assertImmutable(immutableMap("1", "1-1", "2", "2-2"));
        assertImmutable(immutableMap("1", "1-1", "2", "2-2", "3", "3-3"));
        assertImmutable(immutableMap("1", "1-1", "2", "2-2", "3", "3-3", "4", "4-4"));
    }

    @Test
    void shouldHandleStreamToImmutableMap() {
        final Map<String, String> result = immutableMap(
                immutableMap("1", "1-1", "2", "")
                        .entrySet().stream()
                        .filter(entry -> !"".equals(entry.getValue())));
        assertEquals(1, result.size());
        assertTrue(result.containsKey("1"));
    }

    static void assertMutable(Collection<String> collection) {
        assertNotNull(collection);
        collection.add("I am mutable");
    }

    static void assertImmutable(Collection<String> collection) {
        assertNotNull(collection);
        assertThrows(UnsupportedOperationException.class, () -> {
            collection.add("i am not mutable");
        });
    }

    static void assertMutable(Map<String, String> map) {
        assertNotNull(map);
        map.put("I am", "mutable");

    }

    static void assertImmutable(Map<String, String> map) {
        assertNotNull(map);
        assertThrows(UnsupportedOperationException.class, () -> {
            map.put("i am", "not mutable");
        });
    }
}
