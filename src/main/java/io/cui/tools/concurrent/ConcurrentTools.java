package io.cui.tools.concurrent;

import static java.util.concurrent.TimeUnit.NANOSECONDS;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

import lombok.experimental.UtilityClass;

/**
 * Provides some helper-methods taken from com.google.common.util.concurrent package
 *
 * @author Oliver Wolff
 *
 */
@UtilityClass
public class ConcurrentTools {

    /**
     * Invokes {@code unit.}{@link TimeUnit#sleep(long) sleep(sleepFor)} uninterruptibly.
     *
     * @param sleepFor
     *
     */
    public static void sleepUninterruptibly(Duration sleepFor) {
        sleepUninterruptibly(saturatedToNanos(sleepFor), TimeUnit.NANOSECONDS);
    }

    /**
     * Invokes {@code unit.}{@link TimeUnit#sleep(long) sleep(sleepFor)} uninterruptibly.
     *
     * @param sleepFor
     * @param unit
     */
    public static void sleepUninterruptibly(long sleepFor, TimeUnit unit) {
        var interrupted = false;
        try {
            var remainingNanos = unit.toNanos(sleepFor);
            var end = System.nanoTime() + remainingNanos;
            while (true) {
                try {
                    // TimeUnit.sleep() treats negative timeouts just like zero.
                    NANOSECONDS.sleep(remainingNanos);
                    return;
                } catch (InterruptedException e) {
                    interrupted = true;
                    remainingNanos = end - System.nanoTime();
                }
            }
        } finally {
            if (interrupted) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /**
     * Returns the number of nanoseconds of the given duration without throwing or overflowing.
     *
     * <p>
     * Instead of throwing {@link ArithmeticException}, this method silently saturates to either
     * {@link Long#MAX_VALUE} or {@link Long#MIN_VALUE}. This behavior can be useful when
     * decomposing
     * a duration in order to call a legacy API which requires a {@code long, TimeUnit} pair.
     *
     * @author com.google.common.util.concurrent.Internal
     */
    static long saturatedToNanos(Duration duration) {
        // Using a try/catch seems lazy, but the catch block will rarely get invoked (except for
        // durations longer than approximately +/- 292 years).
        try {
            return duration.toNanos();
        } catch (ArithmeticException tooBig) {
            return duration.isNegative() ? Long.MIN_VALUE : Long.MAX_VALUE;
        }
    }
}
