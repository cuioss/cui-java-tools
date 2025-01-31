/*
 * Copyright 2023 the original author or authors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.tools.concurrent;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * @author <a href="https://github.com/google/guava/blob/master/guava-tests/test/com/google/common/util/concurrent/UninterruptiblesTest.java">...</a>
 */
@DisplayName("ConcurrentTools should")
class ConcurrentToolsTest {

    private static final long SLEEP_SLACK = 2;
    private static final long LONG_DELAY_MS = 2500;

    @Nested
    @DisplayName("handle uninterruptible sleep")
    class UninterruptibleSleepTest {

        @Test
        @DisplayName("complete normally without interruption")
        void sleepNoInterrupt() {
            sleepSuccessfully(10);
        }

        @Test
        @DisplayName("complete despite interruption")
        void sleepSingleInterrupt() {
            requestInterruptIn();
            sleepSuccessfully(50);
            assertInterrupted();
        }

        @Test
        @DisplayName("handle Duration parameter")
        void shouldSleepWithDuration() {
            var completed = new Completion(50 - SLEEP_SLACK);
            ConcurrentTools.sleepUninterruptedly(Duration.ofMillis(50));
            completed.assertCompletionExpected();
        }

        @Test
        @DisplayName("handle zero duration")
        void shouldHandleZeroDuration() {
            var completed = new Completion(0);
            ConcurrentTools.sleepUninterruptedly(Duration.ZERO);
            completed.assertCompletionExpected();
        }

        @Test
        @DisplayName("handle negative duration")
        void shouldHandleNegativeDuration() {
            var completed = new Completion(0);
            ConcurrentTools.sleepUninterruptedly(Duration.ofMillis(-10));
            completed.assertCompletionExpected();
        }
    }

    @Nested
    @DisplayName("handle duration conversion")
    class DurationConversionTest {

        @Test
        @DisplayName("handle long overflow")
        void shouldHandleLongOverflow() {
            assertEquals(0L, ConcurrentTools.saturatedToNanos(Duration.ofMillis(Long.MIN_VALUE)),
                    "Should handle minimum long value");
            assertEquals(Long.MAX_VALUE, ConcurrentTools.saturatedToNanos(Duration.ofMillis(Long.MAX_VALUE)),
                    "Should handle maximum long value");
        }

        @Test
        @DisplayName("handle zero and negative durations")
        void shouldHandleZeroAndNegative() {
            assertEquals(0L, ConcurrentTools.saturatedToNanos(Duration.ZERO),
                    "Should handle zero duration");
            assertEquals(0L, ConcurrentTools.saturatedToNanos(Duration.ofNanos(-1)),
                    "Should handle negative duration");
        }
    }

    /**
     * Wrapper around {@link StopWatch} which also contains an "expected completion
     * time." Creating a {@code Completion} starts the underlying stopwatch.
     */
    private static final class Completion {

        final StopWatch stopwatch;
        final long expectedCompletionWaitMillis;

        Completion(long expectedCompletionWaitMillis) {
            this.expectedCompletionWaitMillis = expectedCompletionWaitMillis;
            stopwatch = StopWatch.createStarted();
        }

        /**
         * Asserts that the expected completion time has passed (and not "too much" time
         * beyond that).
         */
        void assertCompletionExpected() {
            assertAtLeastTimePassed(stopwatch, expectedCompletionWaitMillis);
            assertTimeNotPassed(stopwatch, expectedCompletionWaitMillis + LONG_DELAY_MS);
        }
    }

    private static void assertAtLeastTimePassed(StopWatch stopwatch, long expectedMillis) {
        var elapsedMillis = stopwatch.elapsed(MILLISECONDS);
        /*
         * The "+ 5" below is to permit, say, sleep(10) to sleep only 9 milliseconds. We
         * see such behavior sometimes, when running these tests publicly as part of
         * Guava. "+ 5" is probably more generous than it needs to be.
         */
        assertTrue(
                elapsedMillis + 5 >= expectedMillis,
                () -> "Expected elapsed millis to be >= " + expectedMillis + " but was " + elapsedMillis);
    }

    private static void assertTimeNotPassed(StopWatch stopwatch, long timelimitMillis) {
        var elapsedMillis = stopwatch.elapsed(MILLISECONDS);
        assertTrue(elapsedMillis < timelimitMillis,
                () -> "Expected elapsed millis to be < " + timelimitMillis + " but was " + elapsedMillis);
    }

    private static void sleepSuccessfully(long sleepMillis) {
        var completed = new Completion(sleepMillis - SLEEP_SLACK);
        ConcurrentTools.sleepUninterruptedly(sleepMillis, MILLISECONDS);
        completed.assertCompletionExpected();
    }

    /**
     * Interrupts the current thread after sleeping for the specified delay.
     */
    @SuppressWarnings("squid:S2925") // owolff: ok for testing
    static void requestInterruptIn() {
        final var interruptee = Thread.currentThread();
        new Thread(() -> {
            try {
                TimeUnit.MILLISECONDS.sleep(10);
            } catch (InterruptedException wontHappen) {
                throw new AssertionError(wontHappen);
            }
            interruptee.interrupt();
        }).start();
    }

    /**
     * Await an interrupt, then clear the interrupt status. Similar to {@code
     * assertTrue(Thread.interrupted())} except that this version tolerates late
     * interrupts.
     */
    @SuppressWarnings("squid:S2925") // owolff: ok for testing
    private static void assertInterrupted() {
        try {
            /*
             * The sleep() will end immediately if we've already been interrupted or wait
             * patiently for the interrupt if not.
             */
            Thread.sleep(LONG_DELAY_MS);
            fail("Expected thread to be interrupted but it was not");
        } catch (InterruptedException expected) {
            assertNotNull(expected, "InterruptedException should not be null");
        }
    }
}
