package io.cui.tools.concurrent;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import io.cui.tools.base.Preconditions;

@SuppressWarnings("javadoc")
public class FakeTicker extends Ticker {

    private static final long serialVersionUID = 1047851947159622996L;
    private final AtomicLong nanos = new AtomicLong();
    private volatile long autoIncrementStepNanos;

    /** Advances the ticker value by {@code time} in {@code timeUnit}. */
    @SuppressWarnings("GoodTime") // should accept a java.time.Duration
    public FakeTicker advance(long time, TimeUnit timeUnit) {
        return advance(timeUnit.toNanos(time));
    }

    /** Advances the ticker value by {@code nanoseconds}. */
    @SuppressWarnings("GoodTime") // should accept a java.time.Duration
    public FakeTicker advance(long nanoseconds) {
        nanos.addAndGet(nanoseconds);
        return this;
    }

    /**
     * Advances the ticker value by {@code duration}.
     *
     */
    public FakeTicker advance(java.time.Duration duration) {
        return advance(duration.toNanos());
    }

    /**
     * Sets the increment applied to the ticker whenever it is queried.
     *
     * <p>
     * The default behavior is to auto increment by zero. i.e: The ticker is left unchanged when
     * queried.
     */
    @SuppressWarnings("GoodTime") // should accept a java.time.Duration
    public FakeTicker setAutoIncrementStep(long autoIncrementStep, TimeUnit timeUnit) {
        Preconditions.checkArgument(autoIncrementStep >= 0, "May not auto-increment by a negative amount");
        autoIncrementStepNanos = timeUnit.toNanos(autoIncrementStep);
        return this;
    }

    /**
     * Sets the increment applied to the ticker whenever it is queried.
     *
     * <p>
     * The default behavior is to auto increment by zero. i.e: The ticker is left unchanged when
     * queried.
     */
    public FakeTicker setAutoIncrementStep(java.time.Duration autoIncrementStep) {
        return setAutoIncrementStep(autoIncrementStep.toNanos(), TimeUnit.NANOSECONDS);
    }

    @Override
    public long read() {
        return nanos.getAndAdd(autoIncrementStepNanos);
    }
}
