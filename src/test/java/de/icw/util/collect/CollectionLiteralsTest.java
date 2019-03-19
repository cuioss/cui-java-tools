package de.icw.util.collect;

import static de.icw.util.collect.CollectionLiterals.immutableList;
import static de.icw.util.collect.CollectionLiterals.immutableMap;
import static de.icw.util.collect.CollectionLiterals.immutableSet;
import static de.icw.util.collect.CollectionLiterals.immutableSortedSet;
import static de.icw.util.collect.CollectionLiterals.mutableList;
import static de.icw.util.collect.CollectionLiterals.mutableMap;
import static de.icw.util.collect.CollectionLiterals.mutableSet;
import static de.icw.util.collect.CollectionLiterals.mutableSortedSet;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;

import org.junit.jupiter.api.Test;

class CollectionLiteralsTest {

    @Test
    void shouldHandleMutableList() {
        assertMutable(mutableList());
        assertMutable(mutableList("1"));
        assertMutable(mutableList("1", "2"));
        assertMutable(mutableList("1", "2"));
        assertMutable(mutableList(new ArrayList<>()));
        assertMutable(mutableList(Arrays.asList("1", "2")));
        assertMutable(mutableList(Arrays.asList("1", "2").iterator()));
        assertMutable(mutableList(Arrays.asList("1", "2").stream()));
    }

    @Test
    void shouldHandleImmutableList() {
        assertImmutable(immutableList());
        assertImmutable(immutableList("1"));
        assertImmutable(immutableList("1", "2"));
        assertImmutable(immutableList(new ArrayList<>()));
        assertImmutable(immutableList(Arrays.asList("1", "2")));
        assertImmutable(immutableList(Arrays.asList("1", "2").iterator()));
        assertImmutable(immutableList(Arrays.asList("1", "2").stream()));
    }

    @Test
    void shouldHandleMutableSet() {
        assertMutable(mutableSet());
        assertMutable(mutableSet("1"));
        assertMutable(mutableSet("1", "2"));
        assertMutable(mutableSet(new ArrayList<>()));
        assertMutable(mutableSet(Arrays.asList("1", "2")));
        assertMutable(mutableSet(Arrays.asList("1", "2").iterator()));
        assertMutable(mutableSet(Arrays.asList("1", "2").stream()));
    }

    @Test
    void shouldHandleImmutableSet() {
        assertImmutable(immutableSet());
        assertImmutable(immutableSet("1"));
        assertImmutable(immutableSet("1", "2"));
        assertImmutable(immutableSet(Arrays.asList("1", "2").iterator()));
        assertImmutable(immutableSet(Arrays.asList("1", "2").stream()));

    }

    @Test
    void shouldHandleMutableSortedSet() {
        assertMutable(mutableSortedSet());
        assertMutable(mutableSortedSet("1"));
        assertMutable(mutableSortedSet("1", "2"));
        assertMutable(mutableSortedSet(Arrays.asList("1", "2").iterator()));
        assertMutable(mutableSortedSet(Arrays.asList("1", "2").stream()));
    }

    @Test
    void shouldHandleImmutableSortedSet() {
        assertImmutable(immutableSortedSet());
        assertImmutable(immutableSortedSet("1"));
        assertImmutable(immutableSortedSet("1", "2"));
        assertImmutable(immutableSortedSet(Arrays.asList("1", "2").iterator()));
        assertImmutable(immutableSortedSet(Arrays.asList("1", "2").stream()));

    }

    @Test
    void shouldHandleMutableMap() {
        assertMutable(mutableMap());
        assertMutable(mutableMap("1", "1-1"));
        assertMutable(mutableMap("1", "1-1", "2", "2-2"));
        assertMutable(mutableMap("1", "1-1", "2", "2-2", "3", "3-3"));
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

    static final void assertMutable(Collection<String> collection) {
        assertNotNull(collection);
        collection.add("I am mutable");
    }

    static final void assertImmutable(Collection<String> collection) {
        assertNotNull(collection);
        assertThrows(UnsupportedOperationException.class, () -> {
            collection.add("i am not mutable");
        });
    }

    static final void assertMutable(Map<String, String> map) {
        assertNotNull(map);
        map.put("I am", "mutable");

    }

    static final void assertImmutable(Map<String, String> map) {
        assertNotNull(map);
        assertThrows(UnsupportedOperationException.class, () -> {
            map.put("i am", "not mutable");
        });
    }
}
