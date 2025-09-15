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
package de.cuioss.http.security.monitoring;

import de.cuioss.http.security.core.UrlSecurityFailureType;
import org.jspecify.annotations.NonNull;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/**
 * Thread-safe counter for tracking security events by failure type.
 *
 * <p>This class provides a centralized mechanism for counting security violations,
 * enabling monitoring, alerting, and security analytics. It uses atomic operations
 * and concurrent collections to ensure thread safety without locks.</p>
 *
 * <h3>Design Principles</h3>
 * <ul>
 *   <li><strong>Thread Safety</strong> - All operations are atomic and thread-safe</li>
 *   <li><strong>Lock-Free</strong> - Uses lock-free data structures for performance</li>
 *   <li><strong>Memory Efficient</strong> - Only allocates counters for observed failure types</li>
 *   <li><strong>Non-Blocking</strong> - All operations complete in constant time</li>
 * </ul>
 *
 * <h3>Usage Examples</h3>
 * <pre>
 * // Create event counter
 * SecurityEventCounter counter = new SecurityEventCounter();
 *
 * // Increment counters for different failure types
 * long pathTraversalCount = counter.increment(UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED);
 * long encodingCount = counter.increment(UrlSecurityFailureType.DOUBLE_ENCODING);
 *
 * // Query current counts
 * long currentCount = counter.getCount(UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED);
 *
 * // Get all counts for reporting
 * Map&lt;UrlSecurityFailureType, Long&gt; allCounts = counter.getAllCounts();
 *
 * // Reset all counters
 * counter.reset();
 * </pre>
 *
 * <h3>Concurrent Access</h3>
 * <p>This class is designed for high-concurrency environments where multiple threads
 * may be simultaneously incrementing counters for different or the same failure types.
 * All operations are atomic and consistent.</p>
 *
 * <h3>Memory Characteristics</h3>
 * <p>Counters are created lazily - only failure types that have been observed will
 * consume memory. This makes the class efficient even when dealing with the full
 * range of possible {@link UrlSecurityFailureType} values.</p>
 *
 * Implements: Task S1 from HTTP verification specification
 *
 * @since 2.5
 * @see UrlSecurityFailureType
 */
public class SecurityEventCounter {

    private final ConcurrentHashMap<UrlSecurityFailureType, AtomicLong> counters = new ConcurrentHashMap<>();

    /**
     * Increments the counter for the specified failure type and returns the new count.
     *
     * <p>This operation is atomic and thread-safe. If this is the first time the failure
     * type has been observed, a new counter will be created and initialized to 1.</p>
     *
     * @param failureType The type of security failure to increment. Must not be null.
     * @return The new count value after incrementing
     * @throws NullPointerException if failureType is null
     */
    public long increment(@NonNull UrlSecurityFailureType failureType) {

        return counters.computeIfAbsent(failureType, k -> new AtomicLong(0))
                .incrementAndGet();
    }

    /**
     * Increments the counter for the specified failure type by the given delta.
     *
     * <p>This operation is atomic and thread-safe. If this is the first time the failure
     * type has been observed, a new counter will be created and initialized to the delta value.</p>
     *
     * @param failureType The type of security failure to increment. Must not be null.
     * @param delta The amount to add to the counter. Must be positive.
     * @return The new count value after incrementing
     * @throws NullPointerException if failureType is null
     * @throws IllegalArgumentException if delta is negative
     */
    public long incrementBy(@NonNull UrlSecurityFailureType failureType, long delta) {
        if (failureType == null) {
            throw new NullPointerException("failureType must not be null");
        }
        if (delta < 0) {
            throw new IllegalArgumentException("delta must be non-negative, got: " + delta);
        }

        return counters.computeIfAbsent(failureType, k -> new AtomicLong(0))
                .addAndGet(delta);
    }

    /**
     * Returns the current count for the specified failure type.
     *
     * <p>Returns 0 if no events of this type have been recorded. This operation
     * is thread-safe and returns a consistent snapshot of the counter value.</p>
     *
     * @param failureType The failure type to query. Must not be null.
     * @return The current count for the failure type, or 0 if no events recorded
     * @throws NullPointerException if failureType is null
     */
    public long getCount(@NonNull UrlSecurityFailureType failureType) {
        if (failureType == null) {
            throw new NullPointerException("failureType must not be null");
        }

        return Optional.ofNullable(counters.get(failureType))
                .map(AtomicLong::get)
                .orElse(0L);
    }

    /**
     * Returns a snapshot of all current counts.
     *
     * <p>Returns an immutable map containing all observed failure types and their
     * current counts. Only failure types with non-zero counts are included.
     * This is useful for reporting and monitoring purposes.</p>
     *
     * @return An immutable map of failure types to their current counts
     */
    public Map<UrlSecurityFailureType, Long> getAllCounts() {
        return counters.entrySet().stream()
                .collect(Collectors.toUnmodifiableMap(
                        Map.Entry::getKey,
                        entry -> entry.getValue().get()
                ));
    }

    /**
     * Returns the total count across all failure types.
     *
     * <p>This method sums all individual counters to provide a total count of
     * security events. Note that this is a snapshot in time and may not be
     * consistent across concurrent modifications.</p>
     *
     * @return The total count of all security events
     */
    public long getTotalCount() {
        return counters.values().stream()
                .mapToLong(AtomicLong::get)
                .sum();
    }

    /**
     * Returns the number of distinct failure types that have been observed.
     *
     * <p>This returns the number of different {@link UrlSecurityFailureType} values
     * that have had at least one event recorded.</p>
     *
     * @return The number of distinct failure types with recorded events
     */
    public int getFailureTypeCount() {
        return counters.size();
    }

    /**
     * Checks if any events have been recorded for the specified failure type.
     *
     * @param failureType The failure type to check. Must not be null.
     * @return true if at least one event has been recorded for this failure type
     * @throws NullPointerException if failureType is null
     */
    public boolean hasEvents(@NonNull UrlSecurityFailureType failureType) {
        return getCount(failureType) > 0;
    }

    /**
     * Checks if any security events have been recorded at all.
     *
     * @return true if any security events have been recorded
     */
    public boolean hasAnyEvents() {
        return !counters.isEmpty() && getTotalCount() > 0;
    }

    /**
     * Resets the counter for a specific failure type to zero.
     *
     * <p>This atomically sets the counter for the specified failure type to zero.
     * If no events have been recorded for this failure type, this operation has no effect.</p>
     *
     * @param failureType The failure type to reset. Must not be null.
     * @throws NullPointerException if failureType is null
     */
    public void reset(@NonNull UrlSecurityFailureType failureType) {
        if (failureType == null) {
            throw new NullPointerException("failureType must not be null");
        }

        AtomicLong counter = counters.get(failureType);
        if (counter != null) {
            counter.set(0);
        }
    }

    /**
     * Resets all counters to zero.
     *
     * <p>This atomically resets all failure type counters to zero. The failure types
     * remain in the internal map but with zero counts. This is useful for periodic
     * reporting cycles where you want to start fresh counts.</p>
     */
    public void reset() {
        counters.values().forEach(counter -> counter.set(0));
    }

    /**
     * Completely clears all counters and removes failure types from tracking.
     *
     * <p>This removes all failure types from the internal map, effectively returning
     * the counter to its initial state. This is more aggressive than {@link #reset()}
     * as it also frees the memory used by the counter objects.</p>
     */
    public void clear() {
        counters.clear();
    }

    /**
     * Returns a string representation of the counter state.
     *
     * <p>This includes the total count and the number of distinct failure types being tracked.
     * It does not include detailed counts to avoid exposing potentially sensitive information.</p>
     *
     * @return A string representation of the counter state
     */
    @Override
    public String toString() {
        return "SecurityEventCounter{totalEvents=%d, distinctFailureTypes=%d}".formatted(
                getTotalCount(), getFailureTypeCount());
    }
}