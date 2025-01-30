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

import static java.util.concurrent.TimeUnit.NANOSECONDS;

import lombok.experimental.UtilityClass;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * Provides some helper-methods taken from com.google.common.util.concurrent
 * package
 *
 * @author Oliver Wolff
 *
 */
@UtilityClass
public class ConcurrentTools {

    /**
     * Invokes {@code unit.}{@link TimeUnit#sleep(long) sleep(sleepFor)}
     * uninterruptibly.
     *
     * @param sleepFor
     *
     */
    public static void sleepUninterruptibly(Duration sleepFor) {
        sleepUninterruptibly(saturatedToNanos(sleepFor), TimeUnit.NANOSECONDS);
    }

    /**
     * Invokes {@code unit.}{@link TimeUnit#sleep(long) sleep(sleepFor)}
     * uninterruptibly.
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
     * Convert the given duration to nanoseconds, saturating at {@link Long#MAX_VALUE}
     * in case of overflow and {@link Long#MIN_VALUE} in case of negative durations.
     *
     * @param duration to be converted
     * @return the duration in nanoseconds
     */
    private static long saturatedToNanos(Duration duration) {
        if (duration.isNegative()) {
            return Long.MIN_VALUE;
        }
        try {
            return duration.toNanos();
        } catch (ArithmeticException e) {
            return Long.MAX_VALUE;
        }
    }
}
