package de.icw.util.collect;

import static de.icw.util.collect.CollectionLiterals.mutableList;
import static de.icw.util.collect.MoreCollections.isEmpty;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

class MoreCollectionsTest {

    @Test
    void shouldDetermineEmptinessForVarags() {
        assertFalse(isEmpty("1"));
        assertFalse(isEmpty("1", "2"));
        assertTrue(isEmpty(Collections.emptyList().toArray()));
        assertTrue(isEmpty((Object[]) null));
    }

    @Test
    void shouldDetermineEmptinessForIterable() {
        assertFalse(isEmpty((Iterable<?>) mutableList("1")));
        assertFalse(isEmpty((Iterable<?>) mutableList("1", "2")));
        assertTrue(isEmpty((Iterable<?>) Collections.emptyList()));
        assertTrue(isEmpty((Iterable<?>) null));
    }

    @Test
    void shouldDetermineEmptinessForCollection() {
        assertFalse(isEmpty(mutableList("1")));
        assertFalse(isEmpty(mutableList("1", "2")));
        assertTrue(isEmpty(Collections.emptyList()));
        assertTrue(isEmpty((Collection<?>) null));
    }

    @Test
    void shouldDetermineEmptinessForIterator() {
        assertFalse(isEmpty(mutableList("1").iterator()));
        assertFalse(isEmpty(mutableList("1", "2").iterator()));
        assertTrue(isEmpty(Collections.emptyList().iterator()));
        assertTrue(isEmpty((Iterator<?>) null));
    }

    @Test
    void shouldDetermineEmptinessForStream() {
        assertFalse(isEmpty(mutableList("1").stream()));
        assertFalse(isEmpty(Collections.emptyList().stream()));
        assertTrue(isEmpty((Stream<?>) null));
    }

}
