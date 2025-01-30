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

import static de.cuioss.tools.base.Preconditions.checkState;
import static java.util.Objects.requireNonNull;
import static java.util.concurrent.TimeUnit.DAYS;
import static java.util.concurrent.TimeUnit.HOURS;
import static java.util.concurrent.TimeUnit.MICROSECONDS;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.NANOSECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.io.Serial;
import java.io.Serializable;
import java.time.Duration;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

/**
 * An object that measures elapsed time in nanoseconds. It is useful to measure
 * elapsed time using this class instead of direct calls to
 * {@link System#nanoTime} for a few reasons:
 *
 * <ul>
 * <li>An alternate time source can be substituted, for testing or performance
 * reasons.
 * <li>As documented by {@code nanoTime}, the value returned has no absolute
 * meaning, and can only be interpreted as relative to another timestamp
 * returned by {@code nanoTime} at a different time. {@code StopWatch} is a more
 * effective abstraction because it exposes only these relative values, not the
 * absolute ones.
 * </ul>
 *
 * <p>
 * Basic usage:
 *
 * <pre>
 *
 * StopWatch stopwatch = StopWatch.createStarted();
 * doSomething();
 * stopwatch.stop(); // optional
 *
 * Duration duration = stopwatch.elapsed();
 *
 * log.info("time: " + stopwatch); // formatted string like "12.3 ms"
 * </pre>
 *
 * <p>
 * StopWatch methods are not idempotent; it is an error to start or stop a
 * stopwatch that is already in the desired state.
 *
 * <p>
 * When testing code that uses this class, use {@link #createUnstarted(Ticker)}
 * or {@link #createStarted(Ticker)} to supply a fake or mock ticker. This
 * allows you to simulate any valid behavior of the stopwatch.
 *
 * <p>
 * <b>Note:</b> This class is not thread-safe.
 *
 * @author com.google.common.base.Stopwatch
 */
public final class StopWatch implements Serializable {

    @Serial
    private static final long serialVersionUID = 4764741831457507136L;

    private final Ticker ticker;
    private boolean isRunning;
    private long elapsedNanos;
    private long startTick;

    /**
     * @return a created (but not started) new stopwatch using
     *         {@link System#nanoTime} as its time source.
     *
     */
    public static StopWatch createUnstarted() {
        return new StopWatch();
    }

    /**
     * @param ticker specified time source, must not be null
     * @return a created (but not started) new stopwatch, using the specified time
     *         source.
     *
     */
    public static StopWatch createUnstarted(Ticker ticker) {
        return new StopWatch(ticker);
    }

    /**
     * @return a created (and started) new stopwatch using {@link System#nanoTime}
     *         as its time source.
     *
     */
    public static StopWatch createStarted() {
        return new StopWatch().start();
    }

    /**
     * @param ticker specified time source, must not be null
     * @return a created (and started) new stopwatch, using the specified time
     *         source.
     *
     */
    public static StopWatch createStarted(Ticker ticker) {
        return new StopWatch(ticker).start();
    }

    StopWatch() {
        ticker = new Ticker();
    }

    StopWatch(Ticker ticker) {
        this.ticker = requireNonNull(ticker, "ticker");
    }

    /**
     * @return {@code true} if {@link #start()} has been called on this stopwatch,
     *         and {@link #stop()} has not been called since the last call to
     *         {@code start()}.
     */
    public boolean isRunning() {
        return isRunning;
    }

    /**
     * Starts the stopwatch.
     *
     * @return this {@code StopWatch} instance
     * @throws IllegalStateException if the stopwatch is already running.
     */
    public StopWatch start() {
        checkState(!isRunning, "This stopwatch is already running.");
        isRunning = true;
        startTick = ticker.read();
        return this;
    }

    /**
     * Stops the stopwatch. Future reads will return the fixed duration that had
     * elapsed up to this point.
     *
     * @return this {@code StopWatch} instance
     * @throws IllegalStateException if the stopwatch is already stopped.
     */
    public StopWatch stop() {
        var tick = ticker.read();
        checkState(isRunning, "This stopwatch is already stopped.");
        isRunning = false;
        elapsedNanos += tick - startTick;
        return this;
    }

    /**
     * Sets the elapsed time for this stopwatch to zero, and places it in a stopped
     * state.
     *
     * @return this {@code StopWatch} instance
     */
    public StopWatch reset() {
        elapsedNanos = 0;
        isRunning = false;
        return this;
    }

    private long elapsedNanos() {
        return isRunning ? ticker.read() - startTick + elapsedNanos : elapsedNanos;
    }

    /**
     * @param desiredUnit must not be null
     * @return the current elapsed time shown on this stopwatch, expressed in the
     *         desired time unit, with any fraction rounded down.
     *
     *         <p>
     *         <b>Note:</b> the overhead of measurement can be more than a
     *         microsecond, so it is generally not useful to specify
     *         {@link TimeUnit#NANOSECONDS} precision here.
     *
     *         <p>
     *         It is generally not a good idea to use an ambiguous, unitless
     *         {@code long} to represent elapsed time. Therefore, we recommend using
     *         {@link #elapsed()} instead, which returns a strongly-typed
     *         {@link Duration} instance.
     *
     */
    public long elapsed(TimeUnit desiredUnit) {
        return desiredUnit.convert(elapsedNanos(), NANOSECONDS);
    }

    /**
     * @return the current elapsed time shown on this stopwatch as a
     *         {@link Duration}. Unlike {@link #elapsed(TimeUnit)}, this method does
     *         not lose any precision due to rounding.
     *
     */
    public Duration elapsed() {
        return Duration.ofNanos(elapsedNanos());
    }

    /** Returns a string representation of the current elapsed time. */
    @Override
    public String toString() {
        var nanos = elapsedNanos();
        var unit = chooseUnit(nanos);
        var value = Math.round((double) nanos / NANOSECONDS.convert(1, unit) * 1000) / 1000.0;
        return String.format(Locale.ROOT, "%.3f %s", value, abbreviate(unit));
    }

    private static TimeUnit chooseUnit(long nanos) {
        if (DAYS.convert(nanos, NANOSECONDS) > 0) {
            return DAYS;
        }
        if (HOURS.convert(nanos, NANOSECONDS) > 0) {
            return HOURS;
        }
        if (MINUTES.convert(nanos, NANOSECONDS) > 0) {
            return MINUTES;
        }
        if (SECONDS.convert(nanos, NANOSECONDS) > 0) {
            return SECONDS;
        }
        if (MILLISECONDS.convert(nanos, NANOSECONDS) > 0) {
            return MILLISECONDS;
        }
        if (MICROSECONDS.convert(nanos, NANOSECONDS) > 0) {
            return MICROSECONDS;
        }
        return NANOSECONDS;
    }

    private static String abbreviate(TimeUnit unit) {
        return switch (unit) {
            case NANOSECONDS -> "ns";
            case MICROSECONDS -> "\u03bcs"; // μs
            case MILLISECONDS -> "ms";
            case SECONDS -> "s";
            case MINUTES -> "min";
            case HOURS -> "h";
            case DAYS -> "d";
            default -> throw new AssertionError();
        };
    }
}
