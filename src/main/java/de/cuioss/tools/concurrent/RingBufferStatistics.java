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

import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

/**
 * Immutable statistics snapshot from a ring buffer.
 * <p>
 * This record provides comprehensive statistics including sample count,
 * average, and key percentiles (P95, P99). All values are computed at
 * the time of creation and remain constant for the lifetime of the instance.
 * <p>
 * The implementation supports two creation patterns:
 * <ul>
 *   <li>Direct instantiation with pre-computed values</li>
 *   <li>Computation from raw samples via {@link #computeFrom(long[], TimeUnit)}</li>
 * </ul>
 *
 * @param sampleCount total number of samples
 * @param average average duration across all samples, or Duration.ZERO if no samples
 * @param p95 95th percentile duration, or Duration.ZERO if no samples
 * @param p99 99th percentile duration, or Duration.ZERO if no samples
 *
 * @author Oliver Wolff
 * @since 2.5
 */
public record RingBufferStatistics(
int sampleCount,
Duration average,
Duration p95,
Duration p99) {

    /**
     * Creates statistics with validation.
     *
     * @throws IllegalArgumentException if sampleCount is negative
     */
    public RingBufferStatistics {
        if (sampleCount < 0) {
            throw new IllegalArgumentException("Sample count cannot be negative: " + sampleCount);
        }
    }

    /**
     * Computes statistics from raw samples.
     * <p>
     * This method calculates all statistics in a single optimized pass.
     * The input array is sorted to calculate percentiles.
     *
     * @param samples array of sample values (will be sorted)
     * @param timeUnit the time unit of the sample values
     * @return computed statistics
     */
    public static RingBufferStatistics computeFrom(long[] samples, TimeUnit timeUnit) {
        if (samples == null || samples.length == 0) {
            return new RingBufferStatistics(0, Duration.ZERO, Duration.ZERO, Duration.ZERO);
        }

        // Calculate sum for average
        long sum = 0;
        for (long sample : samples) {
            sum += sample;
        }
        long averageValue = sum / samples.length;

        // Sort for percentile calculation
        Arrays.sort(samples);

        // Calculate percentiles
        long p95Value = calculatePercentile(samples, 0.95);
        long p99Value = calculatePercentile(samples, 0.99);

        // Convert to Duration based on TimeUnit
        Duration average = Duration.ofNanos(timeUnit.toNanos(averageValue));
        Duration p95 = Duration.ofNanos(timeUnit.toNanos(p95Value));
        Duration p99 = Duration.ofNanos(timeUnit.toNanos(p99Value));

        return new RingBufferStatistics(samples.length, average, p95, p99);
    }

    /**
     * Calculates a percentile from a sorted array.
     *
     * @param sortedSamples sorted array of samples
     * @param percentile percentile to calculate (0.0 to 1.0)
     * @return percentile value
     */
    private static long calculatePercentile(long[] sortedSamples, double percentile) {
        if (sortedSamples.length == 0) {
            return 0;
        }

        int index = (int) Math.ceil(percentile * sortedSamples.length) - 1;
        index = Math.max(0, Math.min(index, sortedSamples.length - 1));

        return sortedSamples[index];
    }

}