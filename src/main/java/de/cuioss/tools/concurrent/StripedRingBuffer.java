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

import de.cuioss.tools.logging.CuiLogger;

/**
 * High-performance striped ring buffer implementation for concurrent measurements.
 * <p>
 * Uses multiple independent ring buffers (stripes) to minimize contention
 * between threads. Each thread writes to a different stripe based on its
 * hash code, significantly reducing lock contention in high-concurrency scenarios.
 * <p>
 * <strong>Key Performance Features:</strong>
 * <ul>
 *   <li><strong>Lock-free operations:</strong> Uses atomic integers only</li>
 *   <li><strong>Stripe distribution:</strong> Multiple independent buffers reduce contention</li>
 *   <li><strong>Thread affinity:</strong> Thread-local stripe selection for cache efficiency</li>
 *   <li><strong>Power-of-2 sizing:</strong> Efficient bit masking in underlying ring buffers</li>
 * </ul>
 * <p>
 * <strong>Design Pattern:</strong>
 * This follows the striping pattern commonly used in high-performance concurrent
 * data structures. By distributing operations across multiple independent buffers,
 * we achieve better scalability than single-buffer solutions while maintaining
 * the statistical accuracy needed for performance monitoring.
 * <p>
 * <strong>Thread Safety:</strong>
 * All operations are thread-safe and lock-free. Multiple threads can simultaneously
 * record measurements and read statistics without blocking each other.
 *
 * @author Oliver Wolff
 * @since 1.0
 */
public class StripedRingBuffer {

    private static final CuiLogger log = new CuiLogger(StripedRingBuffer.class);

    /**
     * Number of independent ring buffer stripes.
     * Based on available processors to minimize contention.
     */
    private static final int STRIPE_COUNT = Math.max(4, Runtime.getRuntime().availableProcessors());

    /**
     * Array of independent ring buffers.
     */
    private final RingBuffer[] stripes;

    /**
     * Number of stripes in this buffer.
     */
    private final int stripeCount;

    /**
     * Creates a new striped ring buffer with the specified total window size.
     * <p>
     * The window size will be distributed across all stripes. For example,
     * with 8 stripes and window size 100, each stripe will have capacity ~12.
     *
     * @param windowSize total number of samples to maintain across all stripes (must be positive)
     * @throws IllegalArgumentException if windowSize is not positive
     */
    public StripedRingBuffer(int windowSize) {
        if (windowSize <= 0) {
            throw new IllegalArgumentException("Window size must be positive: " + windowSize);
        }

        this.stripeCount = STRIPE_COUNT;
        this.stripes = new RingBuffer[stripeCount];

        // Distribute window size across stripes, ensuring at least 1 per stripe
        int sizePerStripe = Math.max(1, windowSize / stripeCount);
        for (int i = 0; i < stripeCount; i++) {
            stripes[i] = new RingBuffer(sizePerStripe);
        }

        int actualTotalCapacity = sizePerStripe * stripeCount;
        if (actualTotalCapacity != windowSize) {
            log.debug("Striped ring buffer capacity adjusted from {} to {} (distributed across {} stripes)",
                    windowSize, actualTotalCapacity, stripeCount);
        }
    }

    /**
     * Records a measurement in the appropriate stripe for the current thread.
     * <p>
     * This operation is lock-free and designed for maximum performance.
     * The stripe is selected based on the current thread's hash code to
     * distribute load and minimize contention.
     *
     * @param microseconds the measurement value in microseconds (must not be negative)
     * @throws IllegalArgumentException if microseconds is negative
     */
    public void recordMeasurement(long microseconds) {
        if (microseconds < 0) {
            throw new IllegalArgumentException("Microseconds cannot be negative: " + microseconds);
        }

        // Select stripe based on current thread to minimize contention
        // Use absolute value to avoid negative indices
        int stripeIndex = (Thread.currentThread().hashCode() & Integer.MAX_VALUE) % stripeCount;
        stripes[stripeIndex].recordMeasurement(microseconds);
    }

    /**
     * Calculates the average from all measurements across all stripes.
     * <p>
     * This method aggregates statistics from all stripes to provide a
     * comprehensive average. The result is eventually consistent and may
     * include partial updates during concurrent write operations.
     *
     * @return the average value in microseconds, or 0 if no measurements exist
     */
    public long getAverage() {
        long totalSum = 0;
        int totalCount = 0;

        // Aggregate across all stripes
        for (RingBuffer stripe : stripes) {
            RingBufferStatistics stats = stripe.getStatistics();
            totalSum += stats.sum();
            totalCount += stats.count();
        }

        return totalCount > 0 ? totalSum / totalCount : 0;
    }

    /**
     * Gets the total sample count across all stripes.
     * <p>
     * This provides the sum of samples currently stored in all ring buffer stripes.
     * The count may be less than the total window size if not all slots are filled.
     *
     * @return the total number of samples across all stripes
     */
    public int getSampleCount() {
        int totalCount = 0;
        for (RingBuffer stripe : stripes) {
            totalCount += stripe.getStatistics().count();
        }
        return totalCount;
    }

    /**
     * Resets all stripes to empty state.
     * <p>
     * This operation resets all underlying ring buffers, clearing all
     * measurements and resetting counters to zero.
     */
    public void reset() {
        for (RingBuffer stripe : stripes) {
            stripe.reset();
        }
    }

}