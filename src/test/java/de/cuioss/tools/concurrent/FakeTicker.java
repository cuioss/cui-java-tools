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

import de.cuioss.tools.base.Preconditions;

import java.io.Serial;
import java.time.Duration;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

public class FakeTicker extends Ticker {

    @Serial
    private static final long serialVersionUID = 1047851947159622996L;
    private final AtomicLong nanos = new AtomicLong();
    private volatile long autoIncrementStepNanos;

    /** Advances the ticker value by {@code time} in {@code timeUnit}. */
    // should accept a java.time.Duration
    @SuppressWarnings("GoodTime")
    public FakeTicker advance(long time, TimeUnit timeUnit) {
        return advance(timeUnit.toNanos(time));
    }

    /** Advances the ticker value by {@code nanoseconds}. */
    // should accept a java.time.Duration
    @SuppressWarnings("GoodTime")
    public FakeTicker advance(long nanoseconds) {
        nanos.addAndGet(nanoseconds);
        return this;
    }

    /**
     * Advances the ticker value by {@code duration}.
     *
     */
    public FakeTicker advance(Duration duration) {
        return advance(duration.toNanos());
    }

    /**
     * Sets the increment applied to the ticker whenever it is queried.
     *
     * <p>
     * The default behavior is to auto increment by zero. i.e: The ticker is left
     * unchanged when queried.
     */
    // should accept a java.time.Duration
    @SuppressWarnings("GoodTime")
    public FakeTicker setAutoIncrementStep(long autoIncrementStep, TimeUnit timeUnit) {
        Preconditions.checkArgument(autoIncrementStep >= 0, "May not auto-increment by a negative amount");
        autoIncrementStepNanos = timeUnit.toNanos(autoIncrementStep);
        return this;
    }

    /**
     * Sets the increment applied to the ticker whenever it is queried.
     *
     * <p>
     * The default behavior is to auto increment by zero. i.e: The ticker is left
     * unchanged when queried.
     */
    public FakeTicker setAutoIncrementStep(Duration autoIncrementStep) {
        return setAutoIncrementStep(autoIncrementStep.toNanos(), TimeUnit.NANOSECONDS);
    }

    @Override
    public long read() {
        return nanos.getAndAdd(autoIncrementStepNanos);
    }
}
