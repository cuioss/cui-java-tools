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
import java.util.concurrent.TimeUnit;

/**
 * Immutable statistics snapshot from a {@link StripedRingBuffer}.
 * <p>
 * This record provides comprehensive statistics including sample count,
 * P50 (median), and key percentiles (P95, P99). All values are computed at
 * the time of creation and remain constant for the lifetime of the instance.
 * <p>
 * The percentile calculation uses an optimized approach with pre-allocated
 * arrays and efficient sorting for better runtime performance.
 *
 * @param sampleCount total number of samples across all stripes
 * @param p50 50th percentile (median) duration across all samples, or Duration.ZERO if no samples
 * @param p95 95th percentile duration, or Duration.ZERO if no samples
 * @param p99 99th percentile duration, or Duration.ZERO if no samples
 *
 * @author Oliver Wolff
 * @since 2.5
 */
public record StripedRingBufferStatistics(
int sampleCount,
Duration p50,
Duration p95,
Duration p99) {

    /**
     * Computes statistics from the given ring buffer stripes.
     * <p>
     * This method aggregates statistics from all stripes. Since individual
     * RingBufferStatistics already contain percentiles, we need to re-compute
     * them from the aggregated samples for accuracy.
     *
     * @param stripes array of ring buffer stripes
     * @param timeUnit the time unit of the measurements
     * @return computed statistics
     */
    static StripedRingBufferStatistics computeFrom(RingBuffer[] stripes, TimeUnit timeUnit) {
        // First pass: collect all samples and count
        int totalCount = 0;
        long[][] stripeSnapshots = new long[stripes.length][];

        for (int i = 0; i < stripes.length; i++) {
            stripeSnapshots[i] = stripes[i].getSamplesSnapshot();
            totalCount += stripeSnapshots[i].length;
        }

        if (totalCount == 0) {
            return new StripedRingBufferStatistics(0, Duration.ZERO, Duration.ZERO, Duration.ZERO);
        }

        // Pre-allocate array for all samples
        long[] allSamples = new long[totalCount];
        int offset = 0;

        // Aggregate all samples in a single array
        for (long[] stripeSamples : stripeSnapshots) {
            if (stripeSamples.length > 0) {
                System.arraycopy(stripeSamples, 0, allSamples, offset, stripeSamples.length);
                offset += stripeSamples.length;
            }
        }

        // Compute statistics from aggregated samples
        RingBufferStatistics aggregatedStats = RingBufferStatistics.computeFrom(allSamples, timeUnit);

        return new StripedRingBufferStatistics(
                aggregatedStats.sampleCount(),
                aggregatedStats.p50(),
                aggregatedStats.p95(),
                aggregatedStats.p99()
        );
    }
}