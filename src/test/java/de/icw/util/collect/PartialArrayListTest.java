package de.icw.util.collect;

import static de.icw.util.collect.PartialArrayList.emptyList;
import static de.icw.util.collect.PartialArrayList.of;
import static de.icw.util.support.Generators.randomInt;
import static de.icw.util.support.Generators.randomStrings;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collections;

import org.junit.jupiter.api.Test;

class PartialArrayListTest {

    private static final int DEFAULT_SIZE = 10;

    @Test
    void shouldHandleEmptyList() {
        assertTrue(emptyList().isEmpty());
        assertFalse(emptyList().isMoreAvailable());
        assertTrue(of(null, DEFAULT_SIZE).isEmpty());
        assertFalse(of(null, DEFAULT_SIZE).isMoreAvailable());
        assertTrue(of(Collections.emptyList(), DEFAULT_SIZE).isEmpty());
        assertFalse(of(Collections.emptyList(), DEFAULT_SIZE).isMoreAvailable());
    }

    @Test
    void shouldHandleSmallLists() {
        assertFalse(of(randomStrings(DEFAULT_SIZE), DEFAULT_SIZE).isEmpty());
        assertEquals(DEFAULT_SIZE, of(randomStrings(DEFAULT_SIZE), DEFAULT_SIZE).size());
        assertFalse(of(randomStrings(DEFAULT_SIZE), DEFAULT_SIZE).isMoreAvailable());
    }

    @Test
    void shouldHandleLargeLists() {
        // Larger List
        int count = randomInt(1, 256);
        int bigger = count + 1;

        assertFalse(of(randomStrings(bigger), count).isEmpty());
        assertEquals(count, of(randomStrings(bigger), count).size());
        assertTrue(of(randomStrings(bigger), count).isMoreAvailable());
    }
}
