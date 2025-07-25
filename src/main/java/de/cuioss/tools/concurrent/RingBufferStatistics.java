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

/**
 * Immutable statistics snapshot from a ring buffer.
 * <p>
 * This record provides a consistent view of ring buffer statistics at a specific
 * point in time, including the total sum of measurements and the count of samples.
 * The statistics are used to calculate averages and other derived metrics.
 * <p>
 * Using a record ensures immutability and provides automatic equals/hashCode/toString
 * implementations, making it suitable for concurrent environments where statistics
 * snapshots need to be passed between threads.
 *
 * @param sum   the total sum of all measurements in microseconds
 * @param count the number of samples currently in the buffer
 * @author Oliver Wolff
 * @since 1.0
 */
public record RingBufferStatistics(long sum, int count) {

    /**
     * Creates statistics with validation.
     *
     * @param sum   the total sum (must not be negative)
     * @param count the sample count (must not be negative)
     * @throws IllegalArgumentException if sum or count is negative
     */
    public RingBufferStatistics {
        if (sum < 0) {
            throw new IllegalArgumentException("Sum cannot be negative: " + sum);
        }
        if (count < 0) {
            throw new IllegalArgumentException("Count cannot be negative: " + count);
        }
    }

}