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

import java.util.concurrent.atomic.AtomicInteger;

/**
 * High-performance lock-free ring buffer implementation.
 * <p>
 * This class implements a fixed-size circular buffer using atomic operations
 * for thread-safe access without locks. It's optimized for high-frequency
 * write operations with occasional read operations for statistics calculation.
 * <p>
 * <strong>Key Performance Features:</strong>
 * <ul>
 *   <li><strong>Lock-free:</strong> Uses only atomic operations for thread safety</li>
 *   <li><strong>Power-of-2 sizing:</strong> Enables efficient bit masking instead of modulo</li>
 *   <li><strong>Pre-allocated arrays:</strong> Zero garbage collection during recording</li>
 *   <li><strong>Atomic counters:</strong> Thread-safe write position and sample count tracking</li>
 * </ul>
 * <p>
 * <strong>Usage Pattern:</strong>
 * This ring buffer is designed for high-frequency writes from multiple threads
 * with occasional reads for statistics. Write operations are optimized for speed,
 * while read operations provide eventually consistent snapshots.
 * <p>
 * <strong>Capacity:</strong>
 * The actual capacity will be rounded up to the next power of 2 for performance
 * optimization. For example, requesting capacity 100 will result in actual capacity 128.
 *
 * @author Oliver Wolff
 * @since 1.0
 */
public class RingBuffer {

    private static final CuiLogger LOGGER = new CuiLogger(RingBuffer.class);

    /**
     * Storage array for measurements in microseconds.
     */
    private final long[] samples;

    /**
     * Bit mask for efficient index calculation (capacity - 1).
     */
    private final int mask;

    /**
     * Atomic write position counter.
     */
    private final AtomicInteger writeIndex = new AtomicInteger(0);

    /**
     * Atomic sample count (capped at array length).
     */
    private final AtomicInteger sampleCount = new AtomicInteger(0);

    /**
     * Creates a new ring buffer with the specified capacity.
     * <p>
     * The actual capacity will be rounded up to the next power of 2
     * for performance optimization.
     *
     * @param capacity the desired capacity (must be positive)
     * @throws IllegalArgumentException if capacity is not positive
     */
    public RingBuffer(int capacity) {
        if (capacity <= 0) {
            throw new IllegalArgumentException("Capacity must be positive: " + capacity);
        }

        int actualCapacity = nextPowerOfTwo(capacity);
        this.samples = new long[actualCapacity];
        this.mask = actualCapacity - 1;

        if (actualCapacity != capacity) {
            LOGGER.debug("Ring buffer capacity adjusted from %s to %s (next power of 2)",
                    capacity, actualCapacity);
        }
    }

    /**
     * Records a measurement in the ring buffer.
     * <p>
     * This operation is lock-free and designed for maximum performance.
     * The measurement will overwrite the oldest value when the buffer is full.
     *
     * @param microseconds the measurement value in microseconds (must not be negative)
     * @throws IllegalArgumentException if microseconds is negative
     */
    public void recordMeasurement(long microseconds) {
        if (microseconds < 0) {
            throw new IllegalArgumentException("Microseconds cannot be negative: " + microseconds);
        }

        int index = writeIndex.getAndIncrement() & mask;
        samples[index] = microseconds;

        // Update sample count (capped at array length)
        sampleCount.updateAndGet(current -> Math.min(current + 1, samples.length));
    }

    /**
     * Gets current statistics from this ring buffer.
     * <p>
     * This method provides an eventually consistent snapshot of the buffer state.
     * During concurrent writes, the statistics may include partial updates but
     * will be consistent with the state at some point during the call.
     *
     * @return immutable statistics snapshot
     */
    public RingBufferStatistics getStatistics() {
        int count = sampleCount.get();
        if (count == 0) {
            return new RingBufferStatistics(0, 0);
        }

        long sum = 0;
        // Read current samples (may include some inconsistency during concurrent writes,
        // but this is acceptable for performance monitoring where perfect accuracy
        // is less important than minimal overhead)
        for (int i = 0; i < count; i++) {
            sum += samples[i];
        }

        return new RingBufferStatistics(sum, count);
    }

    /**
     * Resets the ring buffer to empty state.
     * <p>
     * This operation resets the write position and sample count.
     * The underlying array is not cleared as samples will be overwritten.
     */
    public void reset() {
        writeIndex.set(0);
        sampleCount.set(0);
    }

    /**
     * Calculates the next power of 2 greater than or equal to the given value.
     * <p>
     * This is used to ensure the ring buffer capacity is a power of 2,
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