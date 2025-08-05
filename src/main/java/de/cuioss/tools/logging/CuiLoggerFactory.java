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
package de.cuioss.tools.logging;

import de.cuioss.tools.collect.CollectionLiterals;
import lombok.experimental.UtilityClass;

import java.util.Collection;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Class provide factory method for CuiLogger instance
 */
@UtilityClass
public class CuiLoggerFactory {

    static final Set<String> MARKER_CLASS_NAMES = CollectionLiterals.immutableSet(CuiLogger.class.getName(),
            CuiLoggerFactory.class.getName());

    private static final Supplier<IllegalStateException> ILLEGAL_STATE_EXCEPTION_SUPPLIER = () -> new IllegalStateException(
            "Unable to detect caller class name. Make sure '" + MARKER_CLASS_NAMES + "' was used for creation.");

    /**
     * Automatic determine the caller class.
     *
     * @return {@link CuiLogger}
     * @throws IllegalStateException if caller couldn't be detected
     */
    public static CuiLogger getLogger() {
        return getLogger(findCallerInternal(MARKER_CLASS_NAMES).orElseThrow(ILLEGAL_STATE_EXCEPTION_SUPPLIER));
    }

    /**
     * Create logger and use the hand-over class name as logger name
     *
     * @param className must not be null
     * @return {@link CuiLogger}
     */
    public static CuiLogger getLogger(final String className) {
        return new CuiLogger(className);
    }

    /**
     * Create logger and use the hand-over class name as logger name
     *
     * @param clazz must not be null
     * @return {@link CuiLogger}
     */
    public static CuiLogger getLogger(final Class<?> clazz) {
        return new CuiLogger(clazz);
    }

    /**
     * Internal method to find the caller class from the stack trace.
     * This is a simplified version that avoids dependency on MoreReflection.
     *
     * @param markerClasses class names which could be used as marker before the
     *                      real caller name. Collection must not be {@code null}.
     * @return option of detected caller class name
     */
    private static Optional<String> findCallerInternal(final Collection<String> markerClasses) {
        Objects.requireNonNull(markerClasses, "Marker class names are missing");

        final StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();

        if (null == stackTraceElements || stackTraceElements.length < 5) {
            return Optional.empty();
        }

        for (var index = 2; index < stackTraceElements.length; index++) {
            final var element = stackTraceElements[index];
            if (markerClasses.contains(element.getClassName())) {
                if (stackTraceElements.length > index + 1) {
                    return Optional.of(stackTraceElements[index + 1].getClassName());
                }
                return Optional.empty();
            }
        }
        return Optional.empty();
    }

}
