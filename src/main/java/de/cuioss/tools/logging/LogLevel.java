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
package de.cuioss.tools.logging;

import static de.cuioss.tools.logging.CuiLoggerFactory.MARKER_CLASS_NAMES;
import static de.cuioss.tools.string.MoreStrings.lenientFormat;
import static de.cuioss.tools.string.MoreStrings.nullToEmpty;

import de.cuioss.tools.collect.CollectionLiterals;
import de.cuioss.tools.reflect.MoreReflection;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import java.util.Comparator;
import java.util.List;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Defines the log-levels with implicit mapping
 *
 * @author Oliver Wolff
 */
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public enum LogLevel {

    /**
     * Trace Level, maps to {@link Level#FINER}.
     * <p>
     * Attention: This is a derivation to
     * <a href="http://www.slf4j.org/apidocs/org/slf4j/bridge/SLF4JBridgeHandler.html">...</a>. But in
     * fact this works...
     */
    TRACE(Level.FINER),

    /**
     * Debug Level, maps to {@link Level#FINE}.
     */
    DEBUG(Level.FINE),

    /**
     * Info Level, maps to {@link Level#INFO}.
     */
    INFO(Level.INFO),

    /**
     * Warn Level, maps to {@link Level#WARNING}.
     */
    WARN(Level.WARNING),

    /**
     * Error Level, maps to {@link Level#SEVERE}.
     */
    ERROR(Level.SEVERE),

    /**
     * Off Level, maps to {@link Level#OFF}
     */
    OFF(Level.OFF);

    @Getter(AccessLevel.PACKAGE)
    private final Level juliLevel;

    /**
     * @param logger to be checked, must not be null
     * @return {@code true} if the log-level is enabled on the logger, false
     *         otherwise
     */
    boolean isEnabled(final Logger logger) {
        return logger.isLoggable(getJuliLevel());
    }

    /**
     * Logs the message
     *
     * @param logger    to be used, must not be null
     * @param message   must not be null
     * @param throwable to be logged, may be null
     */
    void handleActualLog(final Logger logger, final String message, final Throwable throwable) {
        if (!isEnabled(logger)) {
            return;
        }
        doLog(logger, message, throwable);
    }

    /**
     * @param juliLevel
     * @return CUI log level
     */
    public static LogLevel from(@NonNull final Level juliLevel) {
        // highest value first, i.e. OFF, ERROR, WARN, INFO, DEBUG, TRACE
        List<LogLevel> sortedCuiLevels = CollectionLiterals.mutableList(values());
        sortedCuiLevels.sort(Comparator.comparing(logLevel -> logLevel.getJuliLevel().intValue()));
        sortedCuiLevels.sort(Comparator.reverseOrder());

        final var juliIntLevel = juliLevel.intValue();
        for (LogLevel cuiLevel : sortedCuiLevels) {
            final var cuiIntLevel = cuiLevel.getJuliLevel().intValue();
            if (cuiIntLevel <= juliIntLevel) {
                return cuiLevel;
            }
        }
        return TRACE;
    }

    private void doLog(final Logger logger, final String message, final Throwable throwable) {
        // We go up the stack-trace until we found the call from CuiLogger.
        final var caller = MoreReflection.findCallerElement(throwable, MARKER_CLASS_NAMES);
        if (caller.isPresent()) {
            // This is needed because otherwise LogRecord will assume this class and this
            // method as
            // the source of the log-statement
            logger.logp(getJuliLevel(), caller.get().getClassName(), caller.get().getMethodName(), message, throwable);
        } else {
            logger.log(getJuliLevel(), message, throwable);
        }
    }

    @SuppressWarnings("squid:S2629")
    // False positive, logger state explicitly checked
    void log(final Logger logger, final String template, final Object... parameter) {
        if (isEnabled(logger)) {
            final var replacedTemplate = de.cuioss.tools.logging.CuiLogger.SLF4J_PATTERN.matcher(nullToEmpty(template))
                    .replaceAll("%s");
            doLog(logger, lenientFormat(replacedTemplate, parameter), null);
        }
    }

    @SuppressWarnings("squid:S2629")
    // False positive, logger state explicitly checked
    void log(final Logger logger, Supplier<String> message, final Throwable throwable) {
        if (isEnabled(logger)) {
            doLog(logger, message.get(), throwable);
        }
    }

    @SuppressWarnings("squid:S2629")
    // False positive, logger state explicitly checked
    void log(final Logger logger, final Throwable throwable, final String template, final Object... parameter) {
        if (isEnabled(logger)) {
            final var replacedTemplate = de.cuioss.tools.logging.CuiLogger.SLF4J_PATTERN.matcher(nullToEmpty(template))
                    .replaceAll("%s");
            doLog(logger, lenientFormat(replacedTemplate, parameter), throwable);
        }
    }
}
