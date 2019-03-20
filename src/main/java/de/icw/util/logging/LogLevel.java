/**
 * Copyright 2018, InterComponentWare AG
 *
 * NO WARRANTIES OR ANY FURTHER CONDITIONS are implied as to the availability
 * of this source code.
 *
 * In case you receive a copy of this source code you are not permitted
 * to modify, use, or distribute this copy without agreement and an explicit
 * license issued by InterComponentWare AG.
 */
package de.icw.util.logging;

import static com.google.common.base.Strings.nullToEmpty;

import java.util.logging.Level;
import java.util.logging.Logger;

import com.google.common.base.Strings;

/**
 * Defines the log-levels with implicit mapping
 *
 * @author i001428, Oliver Wolff
 *
 */
enum LogLevel {

    /** Trace Level, maps to {@link Level#FINEST}. */
    TRACE(Level.FINEST),
    /** Debug Level, maps to {@link Level#FINE}. */
    DEBUG(Level.FINE),
    /** Info Level, maps to {@link Level#INFO}. */
    INFO(Level.INFO),
    /** Warn Level, maps to {@link Level#WARNING}. */
    WARN(Level.WARNING),
    /** Error Level, maps to {@link Level#SEVERE}. */
    ERROR(Level.SEVERE);

    /**
     * @param juliLevel
     */
    private LogLevel(Level juliLevel) {
        this.juliLevel = juliLevel;
    }

    private final Level juliLevel;

    /**
     * @return the Log-level representation of the log-level
     */
    public Level getJuliLevel() {
        return juliLevel;
    }

    /**
     *
     * @param logger to be checked, must not be null
     * @return {@code true} if the log-level is enable on the logger, false otherwise
     */
    public boolean isEnabled(Logger logger) {
        return logger.isLoggable(getJuliLevel());
    }

    /**
     * Logs the message
     *
     * @param logger to be used, must not be null
     * @param message must not be null
     */
    public void log(Logger logger, String message) {
        logger.log(getJuliLevel(), message);
    }

    /**
     * Logs the message
     *
     * @param logger to be used, must not be null
     * @param message must not be null
     * @param throwable to be logged
     */
    public void log(Logger logger, String message, Throwable throwable) {
        logger.log(getJuliLevel(), message, throwable);
    }

    /**
     * @param logger
     * @param template
     * @param parameter
     */
    @SuppressWarnings("squid:S2629") // False positive, logger state explicitly checked
    public void log(Logger logger, String template, Object... parameter) {
        if (isEnabled(logger)) {
            String replacedTemplate =
                de.icw.util.logging.Logger.SLF4J_PATTERN.matcher(nullToEmpty(template)).replaceAll("%s");
            logger.log(getJuliLevel(), Strings.lenientFormat(replacedTemplate, parameter));
        }
    }
}
