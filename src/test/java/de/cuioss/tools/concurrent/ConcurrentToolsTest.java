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

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;

/**
 * @author <a href="https://github.com/google/guava/blob/master/guava-tests/test/com/google/common/util/concurrent/UninterruptiblesTest.java">...</a>
 *
 */
class ConcurrentToolsTest {

    private static final long SLEEP_SLACK = 2;

    /** Timeout to use when we don't expect the timeout to expire. */
    private static final long LONG_DELAY_MS = 2500;

    @Test
    void testSleepNoInterrupt() {
        sleepSuccessfully(10);
    }

    @Test
    void testSleepSingleInterrupt() {
        requestInterruptIn(10);
        sleepSuccessfully(50);
        assertInterrupted();
    }

    @Test
    void shouldSleepWithDuration() {
        var completed = new Completion(50 - SLEEP_SLACK);
        ConcurrentTools.sleepUninterruptibly(Duration.ofMillis(50));
        completed.assertCompletionExpected();
    }

    @Test
    void shouldHandleLongOverflow() {
        assertEquals(Long.MIN_VALUE, ConcurrentTools.saturatedToNanos(Duration.ofMillis(Long.MIN_VALUE)));
        assertEquals(Long.MAX_VALUE, ConcurrentTools.saturatedToNanos(Duration.ofMillis(Long.MAX_VALUE)));
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
         * see such behavior sometimes when running these tests publicly as part of
         * Guava. "+ 5" is probably more generous than it needs to be.
         */
        assertTrue(

                elapsedMillis + 5 >= expectedMillis,
                "Expected elapsed millis to be >= " + expectedMillis + " but was " + elapsedMillis);
    }

    private static void assertTimeNotPassed(StopWatch stopwatch, long timelimitMillis) {
        var elapsedMillis = stopwatch.elapsed(MILLISECONDS);
        assertTrue(elapsedMillis < timelimitMillis);
    }

    private static void sleepSuccessfully(long sleepMillis) {
        var completed = new Completion(sleepMillis - SLEEP_SLACK);
        ConcurrentTools.sleepUninterruptibly(sleepMillis, MILLISECONDS);
        completed.assertCompletionExpected();
    }

    /** Interrupts the current thread after sleeping for the specified delay. */
    @SuppressWarnings("squid:S2925") // owolff: ok for testing
    static void requestInterruptIn(final long time) {
        final var interruptee = Thread.currentThread();
        new Thread(() -> {
            try {
                TimeUnit.MILLISECONDS.sleep(time);
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
            fail("Dude, where's my interrupt?");
        } catch (InterruptedException expected) {
        }
    }
}
