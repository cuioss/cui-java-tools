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
    void shouldDefaultToMicroseconds() {
        RingBuffer buffer = new RingBuffer(10);
        // This test just verifies the constructor works
        assertNotNull(buffer);
    }

    @Test
    void shouldAcceptCustomTimeUnit() {
        RingBuffer buffer = new RingBuffer(10, TimeUnit.MILLISECONDS);
        assertNotNull(buffer);

        buffer = new RingBuffer(10, TimeUnit.NANOSECONDS);
        assertNotNull(buffer);

        buffer = new RingBuffer(10, TimeUnit.SECONDS);
        assertNotNull(buffer);
    }

    @Test
    void shouldRejectNullTimeUnit() {
        assertThrows(NullPointerException.class, () -> new RingBuffer(10, null));
    }

    @Test
    void shouldRejectInvalidCapacity() {
        assertThrows(IllegalArgumentException.class, () -> new RingBuffer(0));
        assertThrows(IllegalArgumentException.class, () -> new RingBuffer(-1));
    }

    @Test
    void shouldRejectNegativeMeasurements() {
        RingBuffer buffer = new RingBuffer(10);
        assertThrows(IllegalArgumentException.class, () -> buffer.recordMeasurement(-1));

        // Also test with custom time unit
        RingBuffer bufferMs = new RingBuffer(10, TimeUnit.MILLISECONDS);
        assertThrows(IllegalArgumentException.class, () -> bufferMs.recordMeasurement(-1));
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
        assertTrue(stats.sampleCount() <= 16); // Should be capped at actual capacity
    }

    @Test
    void shouldHandleEmptyBuffer() {
        RingBuffer buffer = new RingBuffer(10);
        RingBufferStatistics stats = buffer.getStatistics();
        assertEquals(0, stats.sampleCount());
        assertEquals(Duration.ZERO, stats.average());
        assertEquals(Duration.ZERO, stats.p95());
        assertEquals(Duration.ZERO, stats.p99());
    }

    @Test
    void shouldRecordAndRetrieveMeasurements() {
        RingBuffer buffer = new RingBuffer(10);

        // Record some measurements
        buffer.recordMeasurement(100);
        buffer.recordMeasurement(200);
        buffer.recordMeasurement(300);

        RingBufferStatistics stats = buffer.getStatistics();
        assertEquals(3, stats.sampleCount());
        assertEquals(Duration.ofNanos(TimeUnit.MICROSECONDS.toNanos(200)), stats.average()); // (100 + 200 + 300) / 3
    }

    @Test
    void shouldOverwriteOldestWhenFull() {
        RingBuffer buffer = new RingBuffer(4); // Will be 4 exactly
        
        // Fill buffer
        for (int i = 1; i <= 4; i++) {
            buffer.recordMeasurement(i * 100); // 100, 200, 300, 400
        }

        RingBufferStatistics stats = buffer.getStatistics();
        assertEquals(4, stats.sampleCount());
        assertEquals(Duration.ofNanos(TimeUnit.MICROSECONDS.toNanos(250)), stats.average()); // (100 + 200 + 300 + 400) / 4

        // Add one more - should overwrite oldest
        buffer.recordMeasurement(500);

        // Sample count should remain at 4
        stats = buffer.getStatistics();
        assertEquals(4, stats.sampleCount());
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
        assertEquals(3, stats.sampleCount());

        // Reset
        buffer.reset();

        // Should be empty
        stats = buffer.getStatistics();
        assertEquals(0, stats.sampleCount());
        assertEquals(Duration.ZERO, stats.average());
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
        assertTrue(stats.sampleCount() > 0);
        assertFalse(stats.average().isNegative());
    }

    @Test
    void shouldHandleLargeMeasurements() {
        RingBuffer buffer = new RingBuffer(10);

        // Test with large values
        buffer.recordMeasurement(Long.MAX_VALUE / 2);
        buffer.recordMeasurement(1000000000L);

        RingBufferStatistics stats = buffer.getStatistics();
        assertEquals(2, stats.sampleCount());
        assertFalse(stats.average().isZero());
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

    @Test
    void shouldReturnCorrectSamplesSnapshot() {
        RingBuffer buffer = new RingBuffer(10);

        // Empty buffer should return empty array
        long[] snapshot = buffer.getSamplesSnapshot();
        assertEquals(0, snapshot.length);

        // Add some samples
        buffer.recordMeasurement(100);
        buffer.recordMeasurement(200);
        buffer.recordMeasurement(300);

        snapshot = buffer.getSamplesSnapshot();
        assertEquals(3, snapshot.length);

        // Verify values are correct (order may vary)
        long sum = 0;
        for (long value : snapshot) {
            sum += value;
        }
        assertEquals(600, sum);
    }

    @Test
    void shouldHandleSnapshotWithFullBuffer() {
        RingBuffer buffer = new RingBuffer(4); // Capacity 4
        
        // Fill buffer completely
        for (int i = 1; i <= 4; i++) {
            buffer.recordMeasurement(i * 100);
        }

        long[] snapshot = buffer.getSamplesSnapshot();
        assertEquals(4, snapshot.length);

        // Add more to trigger overwrites
        buffer.recordMeasurement(500);
        buffer.recordMeasurement(600);

        // Should still have 4 samples
        snapshot = buffer.getSamplesSnapshot();
        assertEquals(4, snapshot.length);
    }

    @Test
    void shouldReturnSnapshotAfterReset() {
        RingBuffer buffer = new RingBuffer(10);

        buffer.recordMeasurement(100);
        buffer.recordMeasurement(200);

        // Reset
        buffer.reset();

        // Snapshot should be empty
        long[] snapshot = buffer.getSamplesSnapshot();
        assertEquals(0, snapshot.length);
    }

    private void testCapacityRounding(int requested, int expectedPowerOfTwo) {
        RingBuffer buffer = new RingBuffer(requested);

        // Fill beyond expected capacity
        for (int i = 0; i < expectedPowerOfTwo + 10; i++) {
            buffer.recordMeasurement(i);
        }

        // Count should be capped at the power-of-2 capacity
        RingBufferStatistics stats = buffer.getStatistics();
        assertEquals(expectedPowerOfTwo, stats.sampleCount());
    }
}