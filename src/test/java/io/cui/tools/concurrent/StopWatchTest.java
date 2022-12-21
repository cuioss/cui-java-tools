package io.cui.tools.concurrent;

import static java.util.concurrent.TimeUnit.MICROSECONDS;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.NANOSECONDS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.time.Duration;

import org.junit.jupiter.api.Test;

/**
 * @author https://github.com/google/guava/blob/master/guava-tests/test/com/google/common/base/StopwatchTest.java
 *
 */
class StopWatchTest {

    private final FakeTicker ticker = new FakeTicker();
    private final StopWatch stopwatch = new StopWatch(ticker);

    @Test
    void testCreateStarted() {
        StopWatch startedStopwatch = StopWatch.createStarted();
        assertTrue(startedStopwatch.isRunning());
    }

    @Test
    void testCreateUnstarted() {
        StopWatch unstartedStopwatch = StopWatch.createUnstarted();
        assertFalse(unstartedStopwatch.isRunning());
        assertEquals(0, unstartedStopwatch.elapsed(NANOSECONDS));
    }

    @Test
    void testInitialState() {
        assertFalse(stopwatch.isRunning());
        assertEquals(0, stopwatch.elapsed(NANOSECONDS));
    }

    @Test
    void testStart() {
        assertSame(stopwatch, stopwatch.start());
        assertTrue(stopwatch.isRunning());
    }

    @Test
    void testStart_whileRunning() {
        stopwatch.start();
        try {
            stopwatch.start();
            fail();
        } catch (IllegalStateException expected) {
        }
        assertTrue(stopwatch.isRunning());
    }

    @Test
    void testStop() {
        stopwatch.start();
        assertSame(stopwatch, stopwatch.stop());
        assertFalse(stopwatch.isRunning());
    }

    @Test
    void testStop_new() {
        try {
            stopwatch.stop();
            fail();
        } catch (IllegalStateException expected) {
        }
        assertFalse(stopwatch.isRunning());
    }

    @Test
    void testStop_alreadyStopped() {
        stopwatch.start();
        stopwatch.stop();
        try {
            stopwatch.stop();
            fail();
        } catch (IllegalStateException expected) {
        }
        assertFalse(stopwatch.isRunning());
    }

    @Test
    void testReset_new() {
        ticker.advance(1);
        stopwatch.reset();
        assertFalse(stopwatch.isRunning());
        ticker.advance(2);
        assertEquals(0, stopwatch.elapsed(NANOSECONDS));
        stopwatch.start();
        ticker.advance(3);
        assertEquals(3, stopwatch.elapsed(NANOSECONDS));
    }

    @Test
    void testReset_whileRunning() {
        ticker.advance(1);
        stopwatch.start();
        assertEquals(0, stopwatch.elapsed(NANOSECONDS));
        ticker.advance(2);
        assertEquals(2, stopwatch.elapsed(NANOSECONDS));
        stopwatch.reset();
        assertFalse(stopwatch.isRunning());
        ticker.advance(3);
        assertEquals(0, stopwatch.elapsed(NANOSECONDS));
    }

    @Test
    void testElapsed_whileRunning() {
        ticker.advance(78);
        stopwatch.start();
        assertEquals(0, stopwatch.elapsed(NANOSECONDS));

        ticker.advance(345);
        assertEquals(345, stopwatch.elapsed(NANOSECONDS));
    }

    @Test
    void testElapsed_notRunning() {
        ticker.advance(1);
        stopwatch.start();
        ticker.advance(4);
        stopwatch.stop();
        ticker.advance(9);
        assertEquals(4, stopwatch.elapsed(NANOSECONDS));
    }

    @Test
    void testElapsed_multipleSegments() {
        stopwatch.start();
        ticker.advance(9);
        stopwatch.stop();

        ticker.advance(16);

        stopwatch.start();
        assertEquals(9, stopwatch.elapsed(NANOSECONDS));
        ticker.advance(25);
        assertEquals(34, stopwatch.elapsed(NANOSECONDS));

        stopwatch.stop();
        ticker.advance(36);
        assertEquals(34, stopwatch.elapsed(NANOSECONDS));
    }

    @Test
    void testElapsed_micros() {
        stopwatch.start();
        ticker.advance(999);
        assertEquals(0, stopwatch.elapsed(MICROSECONDS));
        ticker.advance(1);
        assertEquals(1, stopwatch.elapsed(MICROSECONDS));
    }

    @Test
    void testElapsed_millis() {
        stopwatch.start();
        ticker.advance(999999);
        assertEquals(0, stopwatch.elapsed(MILLISECONDS));
        ticker.advance(1);
        assertEquals(1, stopwatch.elapsed(MILLISECONDS));
    }

    @Test
    void testElapsed_duration() {
        stopwatch.start();
        ticker.advance(999999);
        assertEquals(Duration.ofNanos(999999), stopwatch.elapsed());
        ticker.advance(1);
        assertEquals(Duration.ofMillis(1), stopwatch.elapsed());
    }

    @Test
    void testToString() {
        stopwatch.start();
        assertEquals("0.000 ns", stopwatch.toString());
        ticker.advance(1);
        assertEquals("1.000 ns", stopwatch.toString());
        ticker.advance(998);
        assertEquals("999.0 ns", stopwatch.toString());
        ticker.advance(1);
        assertEquals("1.000 \u03bcs", stopwatch.toString());
        ticker.advance(1);
        assertEquals("1.001 \u03bcs", stopwatch.toString());
        ticker.advance(8998);
        assertEquals("9.999 \u03bcs", stopwatch.toString());
        stopwatch.reset();
        stopwatch.start();
        ticker.advance(1234567);
        assertEquals("1.235 ms", stopwatch.toString());
        stopwatch.reset();
        stopwatch.start();
        ticker.advance(5000000000L);
        assertEquals("5.000 s", stopwatch.toString());
        stopwatch.reset();
        stopwatch.start();
        ticker.advance((long) (1.5 * 60 * 1000000000L));
        assertEquals("1.500 min", stopwatch.toString());
        stopwatch.reset();
        stopwatch.start();
        ticker.advance((long) (2.5 * 60 * 60 * 1000000000L));
        assertEquals("2.500 h", stopwatch.toString());
        stopwatch.reset();
        stopwatch.start();
        ticker.advance((long) (7.25 * 24 * 60 * 60 * 1000000000L));
        assertEquals("7.250 d", stopwatch.toString());
    }

}
