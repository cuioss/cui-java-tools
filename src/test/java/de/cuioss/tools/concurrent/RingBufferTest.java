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

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link RingBuffer}.
 *
 * @author Oliver Wolff
 * @since 1.0
 */
class RingBufferTest {

    @Test
    void shouldRejectInvalidCapacity() {
        assertThrows(IllegalArgumentException.class, () -> new RingBuffer(0));
        assertThrows(IllegalArgumentException.class, () -> new RingBuffer(-1));
    }

    @Test
    void shouldRejectNegativeMeasurements() {
        RingBuffer buffer = new RingBuffer(10);
        assertThrows(IllegalArgumentException.class, () -> buffer.recordMeasurement(-1));
    }

    @Test
    void shouldRoundCapacityToPowerOfTwo() {
        // Test various capacities to ensure power-of-2 rounding works
        RingBuffer buffer = new RingBuffer(10);
        // Should round to 16, fill it up and check count doesn't exceed
        for (int i = 0; i < 20; i++) {
            buffer.recordMeasurement(i);
        }
        RingBufferStatistics stats = buffer.getStatistics();
        assertTrue(stats.count() <= 16); // Should be capped at actual capacity
    }

    @Test
    void shouldHandleEmptyBuffer() {
        RingBuffer buffer = new RingBuffer(10);
        RingBufferStatistics stats = buffer.getStatistics();
        assertEquals(0, stats.sum());
        assertEquals(0, stats.count());
    }

    @Test
    void shouldRecordAndRetrieveMeasurements() {
        RingBuffer buffer = new RingBuffer(10);

        // Record some measurements
        buffer.recordMeasurement(100);
        buffer.recordMeasurement(200);
        buffer.recordMeasurement(300);

        RingBufferStatistics stats = buffer.getStatistics();
        assertEquals(600, stats.sum());
        assertEquals(3, stats.count());
    }

    @Test
    void shouldOverwriteOldestWhenFull() {
        RingBuffer buffer = new RingBuffer(4); // Will be 4 exactly
        
        // Fill buffer
        for (int i = 1; i <= 4; i++) {
            buffer.recordMeasurement(i * 100); // 100, 200, 300, 400
        }

        RingBufferStatistics stats = buffer.getStatistics();
        assertEquals(1000, stats.sum()); // 100 + 200 + 300 + 400
        assertEquals(4, stats.count());

        // Add one more - should overwrite oldest
        buffer.recordMeasurement(500);

        // Sample count should remain at 4
        stats = buffer.getStatistics();
        assertEquals(4, stats.count());
    }

    @Test
    void shouldResetCorrectly() {
        RingBuffer buffer = new RingBuffer(10);

        // Add some measurements
        buffer.recordMeasurement(100);
        buffer.recordMeasurement(200);
        buffer.recordMeasurement(300);

        // Verify they're there
        RingBufferStatistics stats = buffer.getStatistics();
        assertEquals(3, stats.count());

        // Reset
        buffer.reset();

        // Should be empty
        stats = buffer.getStatistics();
        assertEquals(0, stats.sum());
        assertEquals(0, stats.count());
    }

    @Test
    void shouldHandleConcurrentWrites() throws InterruptedException {
        RingBuffer buffer = new RingBuffer(1000);
        int threadCount = 10;
        int measurementsPerThread = 1000;
        CountDownLatch latch = new CountDownLatch(threadCount);

        ExecutorService executor = Executors.newFixedThreadPool(threadCount);

        // Each thread records measurements
        for (int t = 0; t < threadCount; t++) {
            final int threadId = t;
            executor.submit(() -> {
                try {
                    for (int i = 0; i < measurementsPerThread; i++) {
                        buffer.recordMeasurement(threadId * 1000L + i);
                    }
                } finally {
                    latch.countDown();
                }
            });
        }

        // Wait for all threads
        assertTrue(latch.await(10, TimeUnit.SECONDS));
        executor.shutdown();

        // Verify we recorded something (exact count may vary due to overwrites)
        RingBufferStatistics stats = buffer.getStatistics();
        assertTrue(stats.count() > 0);
        assertTrue(stats.sum() > 0);
    }

    @Test
    void shouldHandleLargeMeasurements() {
        RingBuffer buffer = new RingBuffer(10);

        // Test with large values
        buffer.recordMeasurement(Long.MAX_VALUE / 2);
        buffer.recordMeasurement(1000000000L);

        RingBufferStatistics stats = buffer.getStatistics();
        assertEquals(2, stats.count());
        assertTrue(stats.sum() > 0);
    }

    @Test
    void shouldMaintainPowerOfTwoSizes() {
        // Test that various requested sizes result in power-of-2 actual sizes
        testCapacityRounding(1, 1);
        testCapacityRounding(2, 2);
        testCapacityRounding(3, 4);
        testCapacityRounding(5, 8);
        testCapacityRounding(10, 16);
        testCapacityRounding(100, 128);
        testCapacityRounding(1000, 1024);
    }

    private void testCapacityRounding(int requested, int expectedPowerOfTwo) {
        RingBuffer buffer = new RingBuffer(requested);

        // Fill beyond expected capacity
        for (int i = 0; i < expectedPowerOfTwo + 10; i++) {
            buffer.recordMeasurement(i);
        }

        // Count should be capped at the power-of-2 capacity
        RingBufferStatistics stats = buffer.getStatistics();
        assertEquals(expectedPowerOfTwo, stats.count());
    }
}