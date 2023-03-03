package de.cuioss.tools.support;

import java.lang.reflect.InvocationTargetException;

import lombok.experimental.UtilityClass;

/**
 * Helper class used for accessing an exception message in a general way
 *
 * @author Oliver Wolff
 */
@UtilityClass
public final class ExceptionHelper {

    private static final String NO_MESSAGE = "No exception message could be extracted";

    /**
     * Extracts a message from a given throwable in a safe manner. It specially handles
     * {@link InvocationTargetException}
     *
     * @param throwable
     * @return the extract message;
     */
    public static String extractMessageFromThrowable(final Throwable throwable) {
        if (null == throwable) {
            return NO_MESSAGE;
        }
        return throwable.getClass().getSimpleName() + " " + throwable.getMessage();
    }

    /**
     * Extracts a message from a given throwable in a safe manner. It specially handles
     * {@link InvocationTargetException}
     *
     * @param throwable
     * @return the extract message;
     */
    public static String extractCauseMessageFromThrowable(final Throwable throwable) {
        if (null == throwable) {
            return NO_MESSAGE;
        }
        if (throwable instanceof InvocationTargetException) {
            return extractMessageFromThrowable(
                    ((InvocationTargetException) throwable).getTargetException());
        }
        return extractMessageFromThrowable(throwable);
    }
}
