package io.cui.util.collect;

import static io.cui.util.collect.PartialArrayList.emptyList;
import static io.cui.util.collect.PartialArrayList.of;
import static io.cui.util.support.Generators.randomInt;
import static io.cui.util.support.Generators.randomStrings;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collections;

import org.junit.jupiter.api.Test;

import io.cui.util.support.ObjectMethodsAsserts;

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

    @Test
    void shouldImplementObjectContracts() {
        ObjectMethodsAsserts.assertNiceObject(of(randomStrings(4), 4));
    }
}
