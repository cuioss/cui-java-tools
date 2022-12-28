package io.cui.tools.logging;

import static io.cui.tools.reflect.MoreReflection.findCaller;

import java.util.Set;
import java.util.function.Supplier;

import io.cui.tools.collect.CollectionLiterals;
import lombok.experimental.UtilityClass;

/**
 * Class provide factory method for CuiLogger instance
 */
@UtilityClass
public class CuiLoggerFactory {

    static final Set<String> MARKER_CLASS_NAMES =
        CollectionLiterals.immutableSet(CuiLogger.class.getName(), CuiLoggerFactory.class.getName());

    private static final Supplier<IllegalStateException> ILLEGAL_STATE_EXCEPTION_SUPPLIER =
        () -> new IllegalStateException(
                "Unable to detect caller class name. Make sure '" + MARKER_CLASS_NAMES + "' was used for creation.");

    /**
     * Automatic determine the caller class.
     *
     * @return {@link CuiLogger}
     * @throws IllegalStateException if caller couldn't be detected
     */
    public static CuiLogger getLogger() {
        return getLogger(findCaller(MARKER_CLASS_NAMES).orElseThrow(ILLEGAL_STATE_EXCEPTION_SUPPLIER));
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

}
