package de.icw.util.logging;

import static com.google.common.base.Strings.nullToEmpty;
import static java.util.Objects.requireNonNull;

import java.util.regex.Pattern;

import com.google.common.base.Strings;

/**
 * <p>
 * Simple wrapper around {@link java.util.logging.Logger} that simplify its usage. In
 * addition it provides a similar api like slf4j. It is not meant to act as logging-facade like
 * slf4j or jakarta commons logging. It only provides a little syntactic sugar.
 * <p/>
 * <h2>Using</h2>
 * <p>
 * {@code private static final Logger LOG = new Logger(MoreReflection.class);}
 * </p>
 * or
 * <p>
 * {@code private static final Logger LOG = new Logger("SomeLoggerName");}
 * </p>
 * <h2>Formatting</h2>
 * <p>
 * Like slf4j there is a simple way of formatting log-messages. In addition to {@code {}} the
 * formatting supports {@code "%s"} as well. At runtime it replaces the {@code {}} tokens with
 * {@code "%s"} and passes the data to {@link Strings#lenientFormat(String, Object...)} for creating
 * the log-message
 * </p>
 *
 * @author Oliver Wolff
 *
 */
public class Logger {

    private final java.util.logging.Logger delegate;

    static final Pattern SLF4J_PATTERN = Pattern.compile(Pattern.quote("{}"));

    /**
     * @param name to be used for acquiring a concrete {@link java.util.logging.Logger} instance.
     *            Must no be null
     */
    public Logger(Class<?> name) {
        requireNonNull(name);
        delegate = java.util.logging.Logger.getLogger(name.getName());
    }

    /**
     * @param name to be used for acquiring a concrete {@link java.util.logging.Logger} instance.
     *            Must no be null
     */
    public Logger(String name) {
        requireNonNull(nullToEmpty(name));
        delegate = java.util.logging.Logger.getLogger(name);
    }

    /**
     * Is the logger instance enabled for the trace level?
     *
     * @return {@code true} if this Logger is enabled for the trace level,
     *         false otherwise.
     *
     */
    public boolean isTraceEnabled() {
        return LogLevel.TRACE.isEnabled(delegate);
    }

    /**
     * Log a message at the trace level.
     *
     * @param msg the message string to be logged
     *
     */
    public void trace(String msg) {
        LogLevel.TRACE.log(delegate, msg);
    }

    /**
     * Log a message at the trace level.
     *
     * @param msg the message string to be logged
     * @param throwable to be logged
     *
     */
    public void trace(String msg, Throwable throwable) {
        LogLevel.TRACE.log(delegate, msg, throwable);
    }

    /**
     * Log a message at the trace level.
     *
     * @param template to be used for formatting, see class-documentation for details on formatting
     * @param parameter to be used for replacing the placeholder
     *
     */
    public void trace(String template, Object... parameter) {
        LogLevel.TRACE.log(delegate, template, parameter);
    }

    /**
     * Is the logger instance enabled for the debug level?
     *
     * @return {@code true} if this Logger is enabled for the debug level,
     *         false otherwise.
     *
     */
    public boolean isDebugEnabled() {
        return LogLevel.DEBUG.isEnabled(delegate);
    }

    /**
     * Log a message at the debug level.
     *
     * @param msg the message string to be logged
     */
    public void debug(String msg) {
        LogLevel.DEBUG.log(delegate, msg);
    }

    /**
     * Log a message at the debug level.
     *
     * @param msg the message string to be logged
     * @param throwable to be logged
     *
     */
    public void debug(String msg, Throwable throwable) {
        LogLevel.DEBUG.log(delegate, msg, throwable);
    }

    /**
     * Log a message at the debug level.
     *
     * @param template to be used for formatting, see class-documentation for details on formatting
     * @param parameter to be used for replacing the placeholder
     *
     */
    public void debug(String template, Object... parameter) {
        LogLevel.DEBUG.log(delegate, template, parameter);
    }

    /**
     * Is the logger instance enabled for the info level?
     *
     * @return {@code true} if this Logger is enabled for the info level,
     *         false otherwise.
     *
     */
    public boolean isInfoEnabled() {
        return LogLevel.INFO.isEnabled(delegate);
    }

    /**
     * Log a message at the info level.
     *
     * @param msg the message string to be logged
     */
    public void info(String msg) {
        LogLevel.INFO.log(delegate, msg);
    }

    /**
     * Log a message at the info level.
     *
     * @param msg the message string to be logged
     * @param throwable to be logged
     *
     */
    public void info(String msg, Throwable throwable) {
        LogLevel.INFO.log(delegate, msg, throwable);
    }

    /**
     * Log a message at the info level.
     *
     * @param template to be used for formatting, see class-documentation for details on formatting
     * @param parameter to be used for replacing the placeholder
     *
     */
    public void info(String template, Object... parameter) {
        LogLevel.INFO.log(delegate, template, parameter);
    }

    /**
     * Is the logger instance enabled for the warn level?
     *
     * @return {@code true} if this Logger is enabled for the warn level,
     *         false otherwise.
     *
     */
    public boolean isWarnEnabled() {
        return LogLevel.WARN.isEnabled(delegate);
    }

    /**
     * Log a message at the warn level.
     *
     * @param msg the message string to be logged
     */
    public void warn(String msg) {
        LogLevel.WARN.log(delegate, msg);
    }

    /**
     * Log a message at the warn level.
     *
     * @param msg the message string to be logged
     * @param throwable to be logged
     *
     */
    public void warn(String msg, Throwable throwable) {
        LogLevel.WARN.log(delegate, msg, throwable);
    }

    /**
     * Log a message at the warn level.
     *
     * @param template to be used for formatting, see class-documentation for details on formatting
     * @param parameter to be used for replacing the placeholder
     *
     */
    public void warn(String template, Object... parameter) {
        LogLevel.WARN.log(delegate, template, parameter);
    }

    /**
     * Is the logger instance enabled for the error level?
     *
     * @return {@code true} if this Logger is enabled for the error level,
     *         false otherwise.
     *
     */
    public boolean isErrorEnabled() {
        return LogLevel.ERROR.isEnabled(delegate);
    }

    /**
     * Log a message at the error level.
     *
     * @param msg the message string to be logged
     */
    public void error(String msg) {
        LogLevel.ERROR.log(delegate, msg);
    }

    /**
     * Log a message at the error level.
     *
     * @param msg the message string to be logged
     * @param throwable to be logged
     *
     */
    public void error(String msg, Throwable throwable) {
        LogLevel.ERROR.log(delegate, msg, throwable);
    }

    /**
     * Log a message at the error level.
     *
     * @param template to be used for formatting, see class-documentation for details on formatting
     * @param parameter to be used for replacing the placeholder
     *
     */
    public void error(String template, Object... parameter) {
        LogLevel.ERROR.log(delegate, template, parameter);
    }

    java.util.logging.Logger getWrapped() {
        return delegate;
    }
}
