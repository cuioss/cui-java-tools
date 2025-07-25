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

import lombok.experimental.UtilityClass;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

import static java.util.concurrent.TimeUnit.NANOSECONDS;

/**
 * Provides some helper-methods taken from com.google.common.util.concurrent
 * package
 *
 * @author Oliver Wolff
 */
@UtilityClass
public class ConcurrentTools {

    /**
     * Invokes {@code unit.}{@link TimeUnit#sleep(long) sleep(sleepFor)}
     * uninterruptedly.
     *
     * @param sleepFor duration
     */
    public static void sleepUninterruptedly(Duration sleepFor) {
        sleepUninterruptedly(saturatedToNanos(sleepFor), TimeUnit.NANOSECONDS);
    }

    /**
     * Invokes {@code unit.}{@link TimeUnit#sleep(long) sleep(sleepFor)}
     * uninterruptedly.
     *
     * @param sleepFor number
     * @param unit     TimeUnit
     */
    public static void sleepUninterruptedly(long sleepFor, TimeUnit unit) {
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
     * in case of overflow and 0 in case of negative durations.
     *
     * @param duration to be converted
     * @return the duration in nanoseconds
     */
    static long saturatedToNanos(Duration duration) {
        if (duration.isNegative() || duration.isZero()) {
            return 0L;
        }
        try {
            return duration.toNanos();
        } catch (ArithmeticException e) {
            return Long.MAX_VALUE;
        }
    }
}
