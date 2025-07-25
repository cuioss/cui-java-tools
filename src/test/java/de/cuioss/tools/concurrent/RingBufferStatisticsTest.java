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
package de.cuioss.tools.concurrent;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link RingBufferStatistics}.
 *
 * @author Oliver Wolff
 * @since 1.0
 */
class RingBufferStatisticsTest {

    @Test
    void shouldCreateValidStatistics() {
        RingBufferStatistics stats = new RingBufferStatistics(1000, 10);
        assertEquals(1000, stats.sum());
        assertEquals(10, stats.count());
    }

    @Test
    void shouldRejectNegativeSum() {
        assertThrows(IllegalArgumentException.class,
                () -> new RingBufferStatistics(-1, 10));
    }

    @Test
    void shouldRejectNegativeCount() {
        assertThrows(IllegalArgumentException.class,
                () -> new RingBufferStatistics(1000, -1));
    }

    @Test
    void shouldAllowZeroValues() {
        RingBufferStatistics stats = new RingBufferStatistics(0, 0);
        assertEquals(0, stats.sum());
        assertEquals(0, stats.count());
    }

    @Test
    void shouldImplementEqualsAndHashCode() {
        RingBufferStatistics stats1 = new RingBufferStatistics(1000, 10);
        RingBufferStatistics stats2 = new RingBufferStatistics(1000, 10);
        RingBufferStatistics stats3 = new RingBufferStatistics(2000, 10);
        RingBufferStatistics stats4 = new RingBufferStatistics(1000, 20);

        // Test equals
        assertEquals(stats1, stats2);
        assertNotEquals(stats1, stats3);
        assertNotEquals(stats1, stats4);
        assertNotEquals(null, stats1);
        assertNotEquals("not a statistics object", stats1);

        // Test hashCode
        assertEquals(stats1.hashCode(), stats2.hashCode());
    }

    @Test
    void shouldProvideToString() {
        RingBufferStatistics stats = new RingBufferStatistics(1000, 10);
        String toString = stats.toString();
        assertNotNull(toString);
        assertTrue(toString.contains("1000"));
        assertTrue(toString.contains("10"));
    }

    @Test
    void shouldHandleLargeValues() {
        RingBufferStatistics stats = new RingBufferStatistics(Long.MAX_VALUE - 1, Integer.MAX_VALUE);
        assertEquals(Long.MAX_VALUE - 1, stats.sum());
        assertEquals(Integer.MAX_VALUE, stats.count());
    }
}