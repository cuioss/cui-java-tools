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
package de.cuioss.tools.support;

import lombok.experimental.UtilityClass;

import java.lang.reflect.InvocationTargetException;

/**
 * Helper class used for accessing an exception message in a general way
 *
 * @author Oliver Wolff
 */
@UtilityClass
public final class ExceptionHelper {

    private static final String NO_MESSAGE = "No exception message could be extracted";

    /**
     * Extracts a message from a given throwable in a safe manner. It specially
     * handles {@link InvocationTargetException}.
     *
     * @param throwable The throwable from which to extract the message. May be null.
     * @return The extracted message in the format "ExceptionClassName message". If the throwable
     *         is null, returns "No exception message could be extracted".
     */
    public static String extractMessageFromThrowable(final Throwable throwable) {
        if (null == throwable) {
            return NO_MESSAGE;
        }
        return throwable.getClass().getSimpleName() + " " + throwable.getMessage();
    }

    /**
     * Extracts a message from a given throwable's cause in a safe manner. It specially
     * handles {@link InvocationTargetException} by extracting the message from its target exception.
     *
     * @param throwable The throwable from which to extract the cause's message. May be null.
     * @return The extracted message from the cause in the format "ExceptionClassName message".
     *         For {@link InvocationTargetException}, returns the message from the target exception.
     *         If the throwable is null, returns "No exception message could be extracted".
     */
    public static String extractCauseMessageFromThrowable(final Throwable throwable) {
        if (null == throwable) {
            return NO_MESSAGE;
        }
        if (throwable instanceof InvocationTargetException exception) {
            return extractMessageFromThrowable(exception.getTargetException());
        }
        return extractMessageFromThrowable(throwable);
    }
}
