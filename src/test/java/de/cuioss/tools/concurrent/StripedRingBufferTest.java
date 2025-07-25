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
        assertEquals(0, buffer.getAverage());
        assertEquals(0, buffer.getSampleCount());
    }

    @Test
    void shouldRecordAndCalculateAverage() {
        StripedRingBuffer buffer = new StripedRingBuffer(100);

        // Record measurements
        buffer.recordMeasurement(100);
        buffer.recordMeasurement(200);
        buffer.recordMeasurement(300);
        buffer.recordMeasurement(400);

        // Average should be 250
        assertEquals(250, buffer.getAverage());
        assertEquals(4, buffer.getSampleCount());
    }

    @Test
    void shouldResetCorrectly() {
        StripedRingBuffer buffer = new StripedRingBuffer(100);

        // Add measurements
        for (int i = 0; i < 10; i++) {
            buffer.recordMeasurement(i * 100);
        }

        // Verify they're there
        assertTrue(buffer.getSampleCount() > 0);
        assertTrue(buffer.getAverage() > 0);

        // Reset
        buffer.reset();

        // Should be empty
        assertEquals(0, buffer.getAverage());
        assertEquals(0, buffer.getSampleCount());
    }

    @Test
    void shouldDistributeAcrossStripes() {
        StripedRingBuffer buffer = new StripedRingBuffer(100);

        // Record many measurements - they should distribute across stripes
        for (int i = 0; i < 1000; i++) {
            buffer.recordMeasurement(i);
        }

        // Should have recorded something
        assertTrue(buffer.getSampleCount() > 0);
        assertTrue(buffer.getAverage() >= 0);
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
        assertTrue(buffer.getSampleCount() > 0);
        assertTrue(buffer.getAverage() > 0);

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
        assertTrue(buffer.getAverage() > 0);
        assertTrue(buffer.getSampleCount() > 0);
    }

    @Test
    void shouldCalculateAverageWithMixedValues() {
        StripedRingBuffer buffer = new StripedRingBuffer(100);

        // Record a mix of small and large values
        buffer.recordMeasurement(1);
        buffer.recordMeasurement(999);
        buffer.recordMeasurement(500);
        buffer.recordMeasurement(500);

        // Average should be 500
        assertEquals(500, buffer.getAverage());
    }

    @Test
    void shouldHandleLargeValues() {
        StripedRingBuffer buffer = new StripedRingBuffer(100);

        // Test with large values
        long largeValue = 1_000_000_000L; // 1 billion microseconds = 1000 seconds
        buffer.recordMeasurement(largeValue);
        buffer.recordMeasurement(largeValue);

        assertEquals(largeValue, buffer.getAverage());
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
        assertTrue(buffer.getSampleCount() <= 20); // Some reasonable upper bound
    }
}