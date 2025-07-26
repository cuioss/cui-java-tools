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
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link StripedRingBuffer}.
 *
 * @author Oliver Wolff
 * @since 1.0
 */
class StripedRingBufferTest {

    @Test
    void shouldRejectInvalidWindowSize() {
        assertThrows(IllegalArgumentException.class, () -> new StripedRingBuffer(0));
        assertThrows(IllegalArgumentException.class, () -> new StripedRingBuffer(-1));
    }

    @Test
    void shouldRejectNegativeMeasurements() {
        StripedRingBuffer buffer = new StripedRingBuffer(100);
        assertThrows(IllegalArgumentException.class, () -> buffer.recordMeasurement(-1));
    }

    @Test
    void shouldHandleEmptyBuffer() {
        StripedRingBuffer buffer = new StripedRingBuffer(100);
        StripedRingBufferStatistics stats = buffer.getStatistics();
        assertEquals(0, stats.sampleCount());
        assertEquals(Duration.ZERO, stats.average());
        assertEquals(Duration.ZERO, stats.p95());
        assertEquals(Duration.ZERO, stats.p99());
    }

    @Test
    void shouldRecordAndCalculateStatistics() {
        StripedRingBuffer buffer = new StripedRingBuffer(100);

        // Record measurements
        buffer.recordMeasurement(100);
        buffer.recordMeasurement(200);
        buffer.recordMeasurement(300);
        buffer.recordMeasurement(400);

        StripedRingBufferStatistics stats = buffer.getStatistics();
        // Average should be 250
        assertEquals(Duration.ofNanos(TimeUnit.MICROSECONDS.toNanos(250)), stats.average());
        assertEquals(4, stats.sampleCount());
        // P95 and P99 should be at or near the max value
        assertTrue(stats.p95().compareTo(Duration.ofNanos(TimeUnit.MICROSECONDS.toNanos(300))) >= 0);
        assertTrue(stats.p99().compareTo(Duration.ofNanos(TimeUnit.MICROSECONDS.toNanos(300))) >= 0);
    }

    @Test
    void shouldResetCorrectly() {
        StripedRingBuffer buffer = new StripedRingBuffer(100);

        // Add measurements
        for (int i = 0; i < 10; i++) {
            buffer.recordMeasurement(i * 100);
        }

        // Verify they're there
        StripedRingBufferStatistics stats = buffer.getStatistics();
        assertTrue(stats.sampleCount() > 0);
        assertFalse(stats.average().isZero());

        // Reset
        buffer.reset();

        // Should be empty
        stats = buffer.getStatistics();
        assertEquals(Duration.ZERO, stats.average());
        assertEquals(0, stats.sampleCount());
        assertEquals(Duration.ZERO, stats.p95());
        assertEquals(Duration.ZERO, stats.p99());
    }

    @Test
    void shouldDistributeAcrossStripes() {
        StripedRingBuffer buffer = new StripedRingBuffer(100);

        // Record many measurements - they should distribute across stripes
        for (int i = 0; i < 1000; i++) {
            buffer.recordMeasurement(i);
        }

        // Should have recorded something
        StripedRingBufferStatistics stats = buffer.getStatistics();
        assertTrue(stats.sampleCount() > 0);
        assertFalse(stats.average().isNegative());
    }

    @Test
    void shouldHandleConcurrentAccess() throws InterruptedException {
        StripedRingBuffer buffer = new StripedRingBuffer(1000);
        int threadCount = 20;
        int measurementsPerThread = 1000;
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threadCount);
        AtomicLong totalSum = new AtomicLong(0);
        AtomicLong totalCount = new AtomicLong(0);

        ExecutorService executor = Executors.newFixedThreadPool(threadCount);

        // Each thread records measurements
        for (int t = 0; t < threadCount; t++) {
            final int threadId = t;
            executor.submit(() -> {
                try {
                    startLatch.await(); // Wait for all threads to be ready
                    
                    for (int i = 0; i < measurementsPerThread; i++) {
                        long value = threadId * 1000L + i;
                        buffer.recordMeasurement(value);
                        totalSum.addAndGet(value);
                        totalCount.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        // Start all threads simultaneously
        startLatch.countDown();

        // Wait for completion
        assertTrue(doneLatch.await(30, TimeUnit.SECONDS));
        executor.shutdown();

        // Verify measurements were recorded
        StripedRingBufferStatistics stats = buffer.getStatistics();
        assertTrue(stats.sampleCount() > 0);
        assertFalse(stats.average().isZero());

        // Note: We can't verify exact averages due to ring buffer overwrites,
        // but we can verify the buffer is functioning
    }

    @Test
    void shouldHandleSmallWindowSizes() {
        // Test with very small window sizes
        StripedRingBuffer buffer = new StripedRingBuffer(1);

        buffer.recordMeasurement(100);
        buffer.recordMeasurement(200);
        buffer.recordMeasurement(300);

        // Should still work, though capacity will be limited
        StripedRingBufferStatistics stats = buffer.getStatistics();
        assertFalse(stats.average().isZero());
        assertTrue(stats.sampleCount() > 0);
    }

    @Test
    void shouldCalculateStatisticsWithMixedValues() {
        StripedRingBuffer buffer = new StripedRingBuffer(100);

        // Record a mix of small and large values
        buffer.recordMeasurement(1);
        buffer.recordMeasurement(999);
        buffer.recordMeasurement(500);
        buffer.recordMeasurement(500);

        StripedRingBufferStatistics stats = buffer.getStatistics();
        // Average should be 500
        assertEquals(Duration.ofNanos(TimeUnit.MICROSECONDS.toNanos(500)), stats.average());
        // P95 and P99 should be close to or at the max
        assertTrue(stats.p95().compareTo(Duration.ofNanos(TimeUnit.MICROSECONDS.toNanos(500))) >= 0);
        assertTrue(stats.p99().compareTo(Duration.ofNanos(TimeUnit.MICROSECONDS.toNanos(500))) >= 0);
    }

    @Test
    void shouldHandleLargeValues() {
        StripedRingBuffer buffer = new StripedRingBuffer(100);

        // Test with large values
        long largeValue = 1_000_000_000L; // 1 billion microseconds = 1000 seconds
        buffer.recordMeasurement(largeValue);
        buffer.recordMeasurement(largeValue);

        StripedRingBufferStatistics stats = buffer.getStatistics();
        assertEquals(Duration.ofNanos(TimeUnit.MICROSECONDS.toNanos(largeValue)), stats.average());
        assertEquals(Duration.ofNanos(TimeUnit.MICROSECONDS.toNanos(largeValue)), stats.p95());
        assertEquals(Duration.ofNanos(TimeUnit.MICROSECONDS.toNanos(largeValue)), stats.p99());
    }

    @Test
    void shouldMaintainRecentMeasurements() {
        StripedRingBuffer buffer = new StripedRingBuffer(10); // Small window
        
        // Fill with initial values
        for (int i = 0; i < 100; i++) {
            buffer.recordMeasurement(i);
        }

        // The buffer should only maintain recent measurements
        // Due to striping, we can't predict exact values, but count should be limited
        StripedRingBufferStatistics stats = buffer.getStatistics();
        assertTrue(stats.sampleCount() <= 20); // Some reasonable upper bound
    }

    @Test
    void shouldCalculatePercentilesCorrectly() {
        StripedRingBuffer buffer = new StripedRingBuffer(1000); // Larger buffer to hold all values
        
        // Add known values for percentile calculation
        for (int i = 1; i <= 100; i++) {
            buffer.recordMeasurement(i * 10); // 10, 20, 30, ..., 1000
        }

        // Check statistics
        StripedRingBufferStatistics stats = buffer.getStatistics();

        // P99 should be >= P95
        assertTrue(stats.p99().compareTo(stats.p95()) >= 0, "P99 should be >= P95");

        // Due to striping and limited buffer size, values should be within the range we inserted
        Duration p95 = stats.p95();
        Duration p99 = stats.p99();
        assertTrue(p95.compareTo(Duration.ofNanos(TimeUnit.MICROSECONDS.toNanos(10))) >= 0 &&
                p95.compareTo(Duration.ofNanos(TimeUnit.MICROSECONDS.toNanos(1000))) <= 0,
                "P95 should be within range, got: " + p95);
        assertTrue(p99.compareTo(Duration.ofNanos(TimeUnit.MICROSECONDS.toNanos(10))) >= 0 &&
                p99.compareTo(Duration.ofNanos(TimeUnit.MICROSECONDS.toNanos(1000))) <= 0,
                "P99 should be within range, got: " + p99);
    }

    @Test
    void shouldHandlePercentileEdgeCases() {
        StripedRingBuffer buffer = new StripedRingBuffer(100);

        // Empty buffer should return 0
        StripedRingBufferStatistics stats = buffer.getStatistics();
        assertEquals(Duration.ZERO, stats.p95());
        assertEquals(Duration.ZERO, stats.p99());

        // Single value
        buffer.recordMeasurement(42);
        stats = buffer.getStatistics();
        assertEquals(Duration.ofNanos(TimeUnit.MICROSECONDS.toNanos(42)), stats.average());
        assertEquals(Duration.ofNanos(TimeUnit.MICROSECONDS.toNanos(42)), stats.p95());
        assertEquals(Duration.ofNanos(TimeUnit.MICROSECONDS.toNanos(42)), stats.p99());
    }


    @Test
    void shouldCalculatePercentilesWithSkewedDistribution() {
        StripedRingBuffer buffer = new StripedRingBuffer(1000); // Larger buffer to ensure we capture the distribution
        
        // Add mostly small values with a few large outliers
        for (int i = 0; i < 90; i++) {
            buffer.recordMeasurement(10); // 90% are 10
        }
        for (int i = 0; i < 10; i++) {
            buffer.recordMeasurement(1000); // 10% are 1000
        }

        StripedRingBufferStatistics stats = buffer.getStatistics();

        // Basic sanity checks - percentiles should be ordered
        assertTrue(stats.p99().compareTo(stats.p95()) >= 0, "P99 should be >= P95");

        // Values should be within our input range
        Duration p95 = stats.p95();
        Duration p99 = stats.p99();
        assertTrue(p95.compareTo(Duration.ofNanos(TimeUnit.MICROSECONDS.toNanos(10))) >= 0 &&
                p95.compareTo(Duration.ofNanos(TimeUnit.MICROSECONDS.toNanos(1000))) <= 0,
                "P95 should be within range");
        assertTrue(p99.compareTo(Duration.ofNanos(TimeUnit.MICROSECONDS.toNanos(10))) >= 0 &&
                p99.compareTo(Duration.ofNanos(TimeUnit.MICROSECONDS.toNanos(1000))) <= 0,
                "P99 should be within range");
    }
}