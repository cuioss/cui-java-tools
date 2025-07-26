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

import java.time.Duration;
import java.util.concurrent.TimeUnit;

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
        Duration avg = Duration.ofMillis(100);
        Duration p95 = Duration.ofMillis(180);
        Duration p99 = Duration.ofMillis(190);
        RingBufferStatistics stats = new RingBufferStatistics(10, avg, p95, p99);
        assertEquals(10, stats.sampleCount());
        assertEquals(avg, stats.p50());
        assertEquals(p95, stats.p95());
        assertEquals(p99, stats.p99());
    }

    @Test
    void shouldRejectNegativeSampleCount() {
        Duration p50 = Duration.ofMillis(100);
        Duration p95 = Duration.ofMillis(180);
        Duration p99 = Duration.ofMillis(190);
        assertThrows(IllegalArgumentException.class,
                () -> new RingBufferStatistics(-1, p50, p95, p99));
    }


    @Test
    void shouldAllowZeroValues() {
        RingBufferStatistics stats = new RingBufferStatistics(0, Duration.ZERO, Duration.ZERO, Duration.ZERO);
        assertEquals(0, stats.sampleCount());
        assertEquals(Duration.ZERO, stats.p50());
        assertEquals(Duration.ZERO, stats.p95());
        assertEquals(Duration.ZERO, stats.p99());
    }

    @Test
    void shouldImplementEqualsAndHashCode() {
        Duration avg = Duration.ofMillis(100);
        Duration p95 = Duration.ofMillis(180);
        Duration p99 = Duration.ofMillis(190);
        RingBufferStatistics stats1 = new RingBufferStatistics(10, avg, p95, p99);
        RingBufferStatistics stats2 = new RingBufferStatistics(10, avg, p95, p99);
        RingBufferStatistics stats3 = new RingBufferStatistics(10, Duration.ofMillis(200), p95, p99);
        RingBufferStatistics stats4 = new RingBufferStatistics(20, avg, p95, p99);

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
        Duration avg = Duration.ofMillis(100);
        Duration p95 = Duration.ofMillis(180);
        Duration p99 = Duration.ofMillis(190);
        RingBufferStatistics stats = new RingBufferStatistics(10, avg, p95, p99);
        String toString = stats.toString();
        assertNotNull(toString);
        assertTrue(toString.contains("10"));
        // Duration toString format might vary, just check it's present
        assertNotNull(toString);
    }

    @Test
    void shouldHandleLargeValues() {
        Duration large = Duration.ofNanos(Long.MAX_VALUE - 1);
        RingBufferStatistics stats = new RingBufferStatistics(Integer.MAX_VALUE, large, large, large);
        assertEquals(Integer.MAX_VALUE, stats.sampleCount());
        assertEquals(large, stats.p50());
    }

    @Test
    void shouldComputeFromSamples() {
        // Test with empty array
        RingBufferStatistics stats = RingBufferStatistics.computeFrom(new long[0], TimeUnit.MICROSECONDS);
        assertEquals(0, stats.sampleCount());
        assertEquals(Duration.ZERO, stats.p50());
        assertEquals(Duration.ZERO, stats.p95());
        assertEquals(Duration.ZERO, stats.p99());

        // Test with single value
        stats = RingBufferStatistics.computeFrom(new long[]{100}, TimeUnit.MICROSECONDS);
        assertEquals(1, stats.sampleCount());
        assertEquals(Duration.of(100, TimeUnit.MICROSECONDS.toChronoUnit()), stats.p50());
        assertEquals(Duration.of(100, TimeUnit.MICROSECONDS.toChronoUnit()), stats.p95());
        assertEquals(Duration.of(100, TimeUnit.MICROSECONDS.toChronoUnit()), stats.p99());

        // Test with multiple values
        long[] samples = new long[100];
        for (int i = 0; i < 100; i++) {
            samples[i] = i + 1; // 1 to 100
        }
        stats = RingBufferStatistics.computeFrom(samples, TimeUnit.MICROSECONDS);
        assertEquals(100, stats.sampleCount());
        assertEquals(Duration.of(50, TimeUnit.MICROSECONDS.toChronoUnit()), stats.p50()); // median of 1-100 is 50
        assertEquals(Duration.of(95, TimeUnit.MICROSECONDS.toChronoUnit()), stats.p95());
        assertEquals(Duration.of(99, TimeUnit.MICROSECONDS.toChronoUnit()), stats.p99());
    }
}