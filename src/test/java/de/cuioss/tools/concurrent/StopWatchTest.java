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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static java.util.concurrent.TimeUnit.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * @author <a href="https://github.com/google/guava/blob/master/guava-tests/test/com/google/common/base/StopwatchTest.java">...</a>
 */
@DisplayName("StopWatch should")
class StopWatchTest {

    private final FakeTicker ticker = new FakeTicker();
    private final StopWatch stopwatch = new StopWatch(ticker);

    @Nested
    @DisplayName("handle factory methods")
    class FactoryMethodsTest {

        @Test
        @DisplayName("create started stopwatch")
        void createStarted() {
            var startedStopwatch = StopWatch.createStarted();
            assertTrue(startedStopwatch.isRunning(), "Stopwatch should be running");
        }

        @Test
        @DisplayName("create unstarted stopwatch")
        void createUnstarted() {
            var unstartedStopwatch = StopWatch.createUnstarted();
            assertFalse(unstartedStopwatch.isRunning(), "Stopwatch should not be running");
            assertEquals(0, unstartedStopwatch.elapsed(NANOSECONDS), "Elapsed time should be 0");
        }
    }

    @Nested
    @DisplayName("handle state transitions")
    class StateTransitionTest {

        @Test
        @DisplayName("have correct initial state")
        void initialState() {
            assertFalse(stopwatch.isRunning(), "Stopwatch should not be running initially");
            assertEquals(0, stopwatch.elapsed(NANOSECONDS), "Initial elapsed time should be 0");
        }

        @Test
        @DisplayName("start correctly")
        void start() {
            assertSame(stopwatch, stopwatch.start(), "Should return self for chaining");
            assertTrue(stopwatch.isRunning(), "Stopwatch should be running after start");
        }

        @Test
        @DisplayName("throw exception when starting while running")
        void startWhileRunning() {
            stopwatch.start();
            assertThrows(IllegalStateException.class, stopwatch::start,
                    "Should throw when starting already running stopwatch");
            assertTrue(stopwatch.isRunning(), "Stopwatch should still be running");
        }

        @Test
        @DisplayName("stop correctly")
        void stop() {
            stopwatch.start();
            assertSame(stopwatch, stopwatch.stop(), "Should return self for chaining");
            assertFalse(stopwatch.isRunning(), "Stopwatch should not be running after stop");
        }

        @Test
        @DisplayName("throw exception when stopping new stopwatch")
        void stopNew() {
            assertThrows(IllegalStateException.class, stopwatch::stop,
                    "Should throw when stopping new stopwatch");
            assertFalse(stopwatch.isRunning(), "Stopwatch should not be running");
        }

        @Test
        @DisplayName("throw exception when stopping already stopped stopwatch")
        void stopAlreadyStopped() {
            stopwatch.start();
            stopwatch.stop();
            assertThrows(IllegalStateException.class, stopwatch::stop,
                    "Should throw when stopping already stopped stopwatch");
            assertFalse(stopwatch.isRunning(), "Stopwatch should not be running");
        }

        @Test
        @DisplayName("reset new stopwatch")
        void resetNew() {
            ticker.advance(1);
            stopwatch.reset();
            assertFalse(stopwatch.isRunning(), "Stopwatch should not be running after reset");
            ticker.advance(2);
            assertEquals(0, stopwatch.elapsed(NANOSECONDS), "Elapsed time should be 0 after reset");
            stopwatch.start();
            ticker.advance(3);
            assertEquals(3, stopwatch.elapsed(NANOSECONDS), "Should measure time after reset and start");
        }

        @Test
        @DisplayName("reset running stopwatch")
        void resetWhileRunning() {
            ticker.advance(1);
            stopwatch.start();
            assertEquals(0, stopwatch.elapsed(NANOSECONDS), "Initial elapsed time should be 0");
            ticker.advance(2);
            assertEquals(2, stopwatch.elapsed(NANOSECONDS), "Should measure elapsed time");
            stopwatch.reset();
            assertFalse(stopwatch.isRunning(), "Stopwatch should not be running after reset");
            ticker.advance(3);
            assertEquals(0, stopwatch.elapsed(NANOSECONDS), "Elapsed time should be 0 after reset");
        }
    }

    @Nested
    @DisplayName("handle elapsed time")
    class ElapsedTimeTest {

        @Test
        @DisplayName("measure time while running")
        void elapsedWhileRunning() {
            ticker.advance(78);
            stopwatch.start();
            assertEquals(0, stopwatch.elapsed(NANOSECONDS), "Initial elapsed time should be 0");
            ticker.advance(345);
            assertEquals(345, stopwatch.elapsed(NANOSECONDS), "Should measure elapsed time");
        }

        @Test
        @DisplayName("measure time when not running")
        void elapsedNotRunning() {
            ticker.advance(1);
            stopwatch.start();
            ticker.advance(4);
            stopwatch.stop();
            ticker.advance(9);
            assertEquals(4, stopwatch.elapsed(NANOSECONDS), "Should keep last elapsed time");
        }

        @Test
        @DisplayName("measure time across multiple segments")
        void elapsedMultipleSegments() {
            stopwatch.start();
            ticker.advance(9);
            stopwatch.stop();

            ticker.advance(16);

            stopwatch.start();
            assertEquals(9, stopwatch.elapsed(NANOSECONDS), "Should keep previous elapsed time");
            ticker.advance(25);
            assertEquals(34, stopwatch.elapsed(NANOSECONDS), "Should accumulate elapsed time");

            stopwatch.stop();
            ticker.advance(36);
            assertEquals(34, stopwatch.elapsed(NANOSECONDS), "Should keep accumulated time");
        }

        @Test
        @DisplayName("handle microsecond precision")
        void elapsedMicros() {
            stopwatch.start();
            ticker.advance(999);
            assertEquals(0, stopwatch.elapsed(MICROSECONDS), "Should round down to 0 microseconds");
            ticker.advance(1);
            assertEquals(1, stopwatch.elapsed(MICROSECONDS), "Should measure 1 microsecond");
        }

        @Test
        @DisplayName("handle millisecond precision")
        void elapsedMillis() {
            stopwatch.start();
            ticker.advance(999999);
            assertEquals(0, stopwatch.elapsed(MILLISECONDS), "Should round down to 0 milliseconds");
            ticker.advance(1);
            assertEquals(1, stopwatch.elapsed(MILLISECONDS), "Should measure 1 millisecond");
        }

        @Test
        @DisplayName("handle Duration")
        void elapsedDuration() {
            stopwatch.start();
            ticker.advance(999999);
            assertEquals(Duration.ofNanos(999999), stopwatch.elapsed(), "Should measure exact nanoseconds");
            ticker.advance(1);
            assertEquals(Duration.ofMillis(1), stopwatch.elapsed(), "Should measure milliseconds");
        }
    }

    @Nested
    @DisplayName("handle string representation")
    class StringRepresentationTest {

        @Test
        @DisplayName("format elapsed time correctly")
        void testToString() {
            stopwatch.start();
            assertEquals("0.000 ns", stopwatch.toString(), "Should format 0 nanoseconds");
            ticker.advance(1);
            assertEquals("1.000 ns", stopwatch.toString(), "Should format 1 nanosecond");
            ticker.advance(998);
            assertEquals("999.000 ns", stopwatch.toString(), "Should format 999 nanoseconds");
            ticker.advance(1);
            assertEquals("1.000 μs", stopwatch.toString(), "Should format 1 microsecond");
            ticker.advance(1);
            assertEquals("1.001 μs", stopwatch.toString(), "Should format 1.001 microseconds");
            ticker.advance(999998);
            assertEquals("1.001 ms", stopwatch.toString(), "Should format 1 millisecond");
        }
    }
}
