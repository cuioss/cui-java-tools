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
import lombok.NonNull;

import java.util.concurrent.TimeUnit;

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
 * <p>
 * <strong>Time Units:</strong>
 * The striped ring buffer now supports configurable time units. By default, values are
 * interpreted as microseconds for backward compatibility.
 *
 * @author Oliver Wolff
 * @since 2.5
 */
public class StripedRingBuffer {

    private static final CuiLogger LOGGER = new CuiLogger(StripedRingBuffer.class);

    /**
     * Number of independent ring buffer stripes.
     * Based on available processors to minimize contention.
     * Rounded to next power of 2 for efficient bitwise operations.
     */
    private static final int STRIPE_COUNT = nextPowerOfTwo(Math.max(4, Runtime.getRuntime().availableProcessors()));

    /**
     * Array of independent ring buffers.
     */
    private final RingBuffer[] stripes;

    /**
     * Number of stripes in this buffer.
     */
    private final int stripeCount;

    /**
     * Time unit for interpreting measurement values.
     */
    @NonNull
    private final TimeUnit timeUnit;

    /**
     * Creates a new striped ring buffer with the specified total window size, defaulting to microseconds.
     * <p>
     * The window size will be distributed across all stripes. For example,
     * with 8 stripes and window size 100, each stripe will have capacity ~12.
     *
     * @param windowSize total number of samples to maintain across all stripes (must be positive)
     * @throws IllegalArgumentException if windowSize is not positive
     */
    public StripedRingBuffer(int windowSize) {
        this(windowSize, TimeUnit.MICROSECONDS);
    }

    /**
     * Creates a new striped ring buffer with the specified total window size and time unit.
     * <p>
     * The window size will be distributed across all stripes. For example,
     * with 8 stripes and window size 100, each stripe will have capacity ~12.
     *
     * @param windowSize total number of samples to maintain across all stripes (must be positive)
     * @param timeUnit the time unit for measurement values (must not be null)
     * @throws IllegalArgumentException if windowSize is not positive
     * @throws NullPointerException if timeUnit is null
     */
    public StripedRingBuffer(int windowSize, @NonNull TimeUnit timeUnit) {
        if (windowSize <= 0) {
            throw new IllegalArgumentException("Window size must be positive: " + windowSize);
        }

        this.stripeCount = STRIPE_COUNT;
        this.stripes = new RingBuffer[stripeCount];
        this.timeUnit = timeUnit;

        // Distribute window size across stripes, ensuring at least 1 per stripe
        int sizePerStripe = Math.max(1, windowSize / stripeCount);
        for (int i = 0; i < stripeCount; i++) {
            stripes[i] = new RingBuffer(sizePerStripe, timeUnit);
        }

        int actualTotalCapacity = sizePerStripe * stripeCount;
        if (actualTotalCapacity != windowSize) {
            LOGGER.debug("Striped ring buffer capacity adjusted from %s to %s (distributed across %s stripes)",
                    windowSize, actualTotalCapacity, stripeCount);
        }
    }

    /**
     * Records a measurement in the appropriate stripe for the current thread.
     * <p>
     * This operation is lock-free and designed for maximum performance.
     * The stripe is selected based on the current thread's hash code to
     * distribute load and minimize contention.
     * The value is interpreted according to the configured time unit.
     *
     * @param amount the measurement value in the configured time unit (must not be negative)
     * @throws IllegalArgumentException if amount is negative
     */
    public void recordMeasurement(long amount) {
        if (amount < 0) {
            throw new IllegalArgumentException("Amount cannot be negative: " + amount);
        }

        // Select stripe based on current thread to minimize contention
        // Use bitwise AND for efficient stripe selection (stripeCount is power of 2)
        int stripeIndex = (Thread.currentThread().hashCode() & Integer.MAX_VALUE) & (stripeCount - 1);
        stripes[stripeIndex].recordMeasurement(amount);
    }

    /**
     * Gets comprehensive statistics from all measurements across all stripes.
     * <p>
     * This method computes a complete statistics snapshot including sample count,
     * average, P95, and P99 in a single optimized pass. The result is eventually
     * consistent and may include partial updates during concurrent write operations.
     * <p>
     * The implementation is optimized for runtime performance by:
     * <ul>
     *   <li>Pre-allocating arrays based on known sizes</li>
     *   <li>Using System.arraycopy for bulk data transfer</li>
     *   <li>Computing all statistics in a single pass</li>
     *   <li>Avoiding boxing/unboxing overhead</li>
     * </ul>
     *
     * @return immutable statistics snapshot containing sampleCount, average, p95, and p99
     */
    public StripedRingBufferStatistics getStatistics() {
        return StripedRingBufferStatistics.computeFrom(stripes, timeUnit);
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

    /**
     * Calculates the next power of 2 greater than or equal to the given value.
     * <p>
     * This is used to ensure the stripe count is a power of 2,
     * enabling efficient bit masking operations instead of expensive modulo operations.
     *
     * @param value the input value (must be positive)
     * @return the next power of 2
     */
    private static int nextPowerOfTwo(int value) {
        if (value <= 1) return 1;
        return Integer.highestOneBit(value - 1) << 1;
    }

}