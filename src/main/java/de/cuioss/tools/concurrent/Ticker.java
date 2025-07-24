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

import java.io.Serial;
import java.io.Serializable;

/**
 * A time source; returns a time value representing the number of nanoseconds
 * elapsed since some fixed but arbitrary point in time. Note that most users
 * should use {@link StopWatch} instead of interacting with this class directly.
 *
 * <p>
 * <b>Warning:</b> this type can only be used to measure elapsed time, not wall
 * time.
 *
 * @author com.google.common.base.Ticker
 */
public class Ticker implements Serializable {

    @Serial
    private static final long serialVersionUID = -1361587646696392654L;

    /**
     * @return the number of nanoseconds elapsed since this ticker's fixed point of
     * reference.
     */
    public long read() {
        return System.nanoTime();
    }
}
