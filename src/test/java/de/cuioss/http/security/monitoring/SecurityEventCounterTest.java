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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link SecurityEventCounter}
 */
class SecurityEventCounterTest {

    private SecurityEventCounter counter;

    @BeforeEach
    void setUp() {
        counter = new SecurityEventCounter();
    }

    @Test
    @DisplayName("Should start with zero counts for all failure types")
    void shouldStartWithZeroCounts() {
        for (UrlSecurityFailureType failureType : UrlSecurityFailureType.values()) {
            assertEquals(0, counter.getCount(failureType));
            assertFalse(counter.hasEvents(failureType));
        }

        assertFalse(counter.hasAnyEvents());
        assertEquals(0, counter.getTotalCount());
        assertEquals(0, counter.getFailureTypeCount());
        assertTrue(counter.getAllCounts().isEmpty());
    }

    @Test
    @DisplayName("Should increment single counter correctly")
    void shouldIncrementSingleCounter() {
        UrlSecurityFailureType failureType = UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED;

        assertEquals(1, counter.increment(failureType));
        assertEquals(1, counter.getCount(failureType));
        assertTrue(counter.hasEvents(failureType));
        assertTrue(counter.hasAnyEvents());

        assertEquals(2, counter.increment(failureType));
        assertEquals(2, counter.getCount(failureType));

        assertEquals(2, counter.getTotalCount());
        assertEquals(1, counter.getFailureTypeCount());
    }

    @Test
    @DisplayName("Should increment multiple counters independently")
    void shouldIncrementMultipleCounters() {
        UrlSecurityFailureType type1 = UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED;
        UrlSecurityFailureType type2 = UrlSecurityFailureType.DOUBLE_ENCODING;

        counter.increment(type1);
        counter.increment(type1);
        counter.increment(type2);

        assertEquals(2, counter.getCount(type1));
        assertEquals(1, counter.getCount(type2));
        assertEquals(3, counter.getTotalCount());
        assertEquals(2, counter.getFailureTypeCount());

        Map<UrlSecurityFailureType, Long> allCounts = counter.getAllCounts();
        assertEquals(2, allCounts.size());
        assertEquals(2L, allCounts.get(type1));
        assertEquals(1L, allCounts.get(type2));
    }

    @Test
    @DisplayName("Should increment by delta correctly")
    void shouldIncrementByDelta() {
        UrlSecurityFailureType failureType = UrlSecurityFailureType.NULL_BYTE_INJECTION;

        assertEquals(5, counter.incrementBy(failureType, 5));
        assertEquals(5, counter.getCount(failureType));

        assertEquals(8, counter.incrementBy(failureType, 3));
        assertEquals(8, counter.getCount(failureType));

        assertEquals(8, counter.incrementBy(failureType, 0));
        assertEquals(8, counter.getCount(failureType));
    }

    @Test
    @DisplayName("Should reject null failure type")
    void shouldRejectNullFailureType() {
        assertThrows(NullPointerException.class, () -> counter.increment(null));
        assertThrows(NullPointerException.class, () -> counter.incrementBy(null, 1));
        assertThrows(NullPointerException.class, () -> counter.getCount(null));
        assertThrows(NullPointerException.class, () -> counter.hasEvents(null));
        assertThrows(NullPointerException.class, () -> counter.reset(null));
    }

    @Test
    @DisplayName("Should reject negative delta")
    void shouldRejectNegativeDelta() {
        UrlSecurityFailureType failureType = UrlSecurityFailureType.INVALID_ENCODING;

        assertThrows(IllegalArgumentException.class, () -> counter.incrementBy(failureType, -1));
        assertThrows(IllegalArgumentException.class, () -> counter.incrementBy(failureType, -100));
    }

    @Test
    @DisplayName("Should reset specific counter")
    void shouldResetSpecificCounter() {
        UrlSecurityFailureType type1 = UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED;
        UrlSecurityFailureType type2 = UrlSecurityFailureType.DOUBLE_ENCODING;

        counter.increment(type1);
        counter.increment(type2);
        counter.increment(type2);

        assertEquals(1, counter.getCount(type1));
        assertEquals(2, counter.getCount(type2));

        counter.reset(type1);

        assertEquals(0, counter.getCount(type1));
        assertEquals(2, counter.getCount(type2));
        assertFalse(counter.hasEvents(type1));
        assertTrue(counter.hasEvents(type2));
    }

    @Test
    @DisplayName("Should reset all counters")
    void shouldResetAllCounters() {
        UrlSecurityFailureType type1 = UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED;
        UrlSecurityFailureType type2 = UrlSecurityFailureType.DOUBLE_ENCODING;

        counter.increment(type1);
        counter.increment(type2);

        assertTrue(counter.hasAnyEvents());
        assertEquals(2, counter.getTotalCount());

        counter.reset();

        assertEquals(0, counter.getCount(type1));
        assertEquals(0, counter.getCount(type2));
        assertFalse(counter.hasEvents(type1));
        assertFalse(counter.hasEvents(type2));
        assertFalse(counter.hasAnyEvents());
        assertEquals(0, counter.getTotalCount());

        // Failure types should still be tracked (not cleared)
        assertEquals(2, counter.getFailureTypeCount());
    }

    @Test
    @DisplayName("Should clear all counters and failure types")
    void shouldClearAllCounters() {
        UrlSecurityFailureType type1 = UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED;
        UrlSecurityFailureType type2 = UrlSecurityFailureType.DOUBLE_ENCODING;

        counter.increment(type1);
        counter.increment(type2);

        assertEquals(2, counter.getFailureTypeCount());

        counter.clear();

        assertEquals(0, counter.getCount(type1));
        assertEquals(0, counter.getCount(type2));
        assertFalse(counter.hasAnyEvents());
        assertEquals(0, counter.getTotalCount());
        assertEquals(0, counter.getFailureTypeCount());
        assertTrue(counter.getAllCounts().isEmpty());
    }

    @Test
    @DisplayName("Should handle reset on non-existent counter")
    void shouldHandleResetOnNonExistentCounter() {
        UrlSecurityFailureType failureType = UrlSecurityFailureType.CONTROL_CHARACTERS;

        // Reset on counter that was never incremented should not throw
        assertDoesNotThrow(() -> counter.reset(failureType));
        assertEquals(0, counter.getCount(failureType));
    }

    @Test
    @DisplayName("Should return immutable map from getAllCounts")
    void shouldReturnImmutableMap() {
        counter.increment(UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED);

        Map<UrlSecurityFailureType, Long> counts = counter.getAllCounts();

        assertThrows(UnsupportedOperationException.class, () ->
                counts.put(UrlSecurityFailureType.DOUBLE_ENCODING, 5L));
    }

    @Test
    @DisplayName("Should provide meaningful toString")
    void shouldProvideMeaningfulToString() {
        String emptyString = counter.toString();
        assertTrue(emptyString.contains("totalEvents=0"));
        assertTrue(emptyString.contains("distinctFailureTypes=0"));

        counter.increment(UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED);
        counter.increment(UrlSecurityFailureType.DOUBLE_ENCODING);
        counter.increment(UrlSecurityFailureType.DOUBLE_ENCODING);

        String populatedString = counter.toString();
        assertTrue(populatedString.contains("totalEvents=3"));
        assertTrue(populatedString.contains("distinctFailureTypes=2"));
    }

    @RepeatedTest(10)
    @DisplayName("Should be thread-safe under concurrent access")
    void shouldBeThreadSafe() throws InterruptedException {
        final int threadCount = 20;
        final int incrementsPerThread = 100;
        final ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        final CountDownLatch startLatch = new CountDownLatch(1);
        final CountDownLatch completionLatch = new CountDownLatch(threadCount);
        final AtomicReference<Exception> error = new AtomicReference<>();

        UrlSecurityFailureType failureType = UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED;

        // Submit tasks
        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    startLatch.await(); // Wait for all threads to be ready

                    for (int j = 0; j < incrementsPerThread; j++) {
                        counter.increment(failureType);
                    }
                } catch (RuntimeException | InterruptedException e) {
                    error.set(e);
                } finally {
                    completionLatch.countDown();
                }
            });
        }

        // Start all threads simultaneously
        startLatch.countDown();

        // Wait for completion
        assertTrue(completionLatch.await(10, TimeUnit.SECONDS), "Test should complete within timeout");

        executor.shutdown();
        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS), "Executor should terminate within timeout");

        // Verify results
        assertNull(error.get(), "No exceptions should occur during concurrent execution");

        long expectedCount = (long) threadCount * incrementsPerThread;
        assertEquals(expectedCount, counter.getCount(failureType),
                "Counter should have exact expected count despite concurrent access");
        assertEquals(expectedCount, counter.getTotalCount());
        assertEquals(1, counter.getFailureTypeCount());
        assertTrue(counter.hasEvents(failureType));
        assertTrue(counter.hasAnyEvents());
    }

    @Test
    @DisplayName("Should handle concurrent access to multiple counters")
    void shouldHandleConcurrentMultipleCounters() throws InterruptedException {
        final int threadCount = 10;
        final ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        final CountDownLatch completionLatch = new CountDownLatch(threadCount);

        UrlSecurityFailureType[] failureTypes = {
                UrlSecurityFailureType.PATH_TRAVERSAL_DETECTED,
                UrlSecurityFailureType.DOUBLE_ENCODING,
                UrlSecurityFailureType.NULL_BYTE_INJECTION
        };

        // Submit tasks that increment different failure types
        for (int i = 0; i < threadCount; i++) {
            final int threadIndex = i;
            executor.submit(() -> {
                try {
                    UrlSecurityFailureType failureType = failureTypes[threadIndex % failureTypes.length];

                    for (int j = 0; j < 50; j++) {
                        counter.increment(failureType);
                    }
                } finally {
                    completionLatch.countDown();
                }
            });
        }

        // Wait for completion
        assertTrue(completionLatch.await(10, TimeUnit.SECONDS));

        executor.shutdown();
        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));

        // Verify results
        assertEquals(500, counter.getTotalCount()); // 10 threads * 50 increments
        assertEquals(3, counter.getFailureTypeCount());

        for (UrlSecurityFailureType failureType : failureTypes) {
            assertTrue(counter.hasEvents(failureType));
            assertTrue(counter.getCount(failureType) > 0);
        }

        Map<UrlSecurityFailureType, Long> allCounts = counter.getAllCounts();
        assertEquals(3, allCounts.size());

        long totalFromMap = allCounts.values().stream().mapToLong(Long::longValue).sum();
        assertEquals(500, totalFromMap);
    }

    @Test
    @DisplayName("Should handle edge cases with all failure types")
    void shouldHandleAllFailureTypes() {
        // Test with all defined failure types
        UrlSecurityFailureType[] allTypes = UrlSecurityFailureType.values();

        for (int i = 0; i < allTypes.length; i++) {
            counter.incrementBy(allTypes[i], i + 1); // Different count for each type
        }

        assertEquals(allTypes.length, counter.getFailureTypeCount());

        long expectedTotal = 0;
        for (int i = 0; i < allTypes.length; i++) {
            expectedTotal += i + 1;
            assertEquals(i + 1, counter.getCount(allTypes[i]));
            assertTrue(counter.hasEvents(allTypes[i]));
        }

        assertEquals(expectedTotal, counter.getTotalCount());

        Map<UrlSecurityFailureType, Long> allCounts = counter.getAllCounts();
        assertEquals(allTypes.length, allCounts.size());

        // Verify all types are present in the map
        for (UrlSecurityFailureType failureType : allTypes) {
            assertTrue(allCounts.containsKey(failureType));
        }
    }
}