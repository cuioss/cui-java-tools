package io.cui.tools.logging;

import static io.cui.tools.string.MoreStrings.nullToEmpty;
import static java.util.Objects.requireNonNull;

import java.util.function.Supplier;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import io.cui.tools.string.MoreStrings;

/**
 * <p>
 * Wrapper around java-util {@link Logger} that simplifies its usage. In
 * addition it provides a similar api like slf4j. It is not meant to act as logging-facade like
 * slf4j or jakarta-commons-logging. It only provides a little syntactic sugar for the built-in
 * logger.
 * <p/>
 * <h2>Obtaining a logger</h2>
 * <p>
 * {@code private static final CuiLogger log = new CuiLogger(SomeClass.class);}
 * <br />
 * {@code private static final CuiLogger log = new CuiLogger("SomeLoggerName");}
 * <br />
 * {@code private static final CuiLogger log = CuiLoggerFactory.getLogger();}
 * </p>
 * <h2>Logging</h2>
 * <p>
 * {@link CuiLogger} provides an implicit code guard, if used correctly. Used correctly hereby means
 * to either use formatting with parameter or incorporating {@link Supplier} for generating the
 * actual log-message. For other means of creating a message you still can use code guards.
 * </p>
 * <p>
 * {@code log.trace("Parameter-type matches exactly '%s'", assignableSource);} <br />
 * {@code log.debug("Adding found method '%s' on class '%s'", name, clazz);}<br />
 * {@code log.info("Starting up application");}
 * </p>
 * <p>
 * {@code // In order not to mess up with the ellipsis parameter}<br/>
 * {@code // exceptions must be the first parameter}<br/>
 * {@code log.warn(e, "Exception during lenientFormat for '%s'", objectToString); }
 * {@code log.error(e, "Caught an exception"); }
 * </p>
 * <p>
 * {@code log.info(() -> "Supplier can be used as well");}<br/>
 * {@code log.error(e, () -> "Even with exceptions");}
 * <br/>
 * {@code log.trace(() -> "I will only be evaluated if the trace-level for is enabled");}
 * </p>
 * <h2>Formatting</h2>
 * <p>
 * Like slf4j there is a simple way of formatting log-messages. In addition to '{}' the
 * formatting supports '%s' as well. At runtime it replaces the '{}' tokens with
 * '%s' and passes the data to {@link MoreStrings#lenientFormat(String, Object...)} for
 * creating the actual log-message. As a variant providing a {@link Supplier} works as well.
 * </p>
 *
 * @author Oliver Wolff
 *
 */
public class CuiLogger {

    private final Logger delegate;

    static final Pattern SLF4J_PATTERN = Pattern.compile(Pattern.quote("{}"));

    /**
     * @param clazz to be used for acquiring a concrete {@link Logger} instance.
     *            Must no be null
     */
    public CuiLogger(Class<?> clazz) {
        requireNonNull(clazz);
        delegate = Logger.getLogger(clazz.getName());
    }

    /**
     * @param name to be used for acquiring a concrete {@link Logger} instance.
     *            Must no be null
     */
    public CuiLogger(String name) {
        requireNonNull(nullToEmpty(name));
        delegate = Logger.getLogger(name);
    }

    /**
     * Is the logger instance enabled for the trace level?
     *
     * @return {@code true} if this CuiLogger is enabled for the trace level,
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
        LogLevel.TRACE.handleActualLog(delegate, msg, null);
    }

    /**
     * Log a message at the trace level.
     *
     * @param msg the message string to be logged
     *
     */
    public void trace(Supplier<String> msg) {
        LogLevel.TRACE.log(delegate, msg, null);
    }

    /**
     * Log a message at the trace level.
     *
     * @param throwable to be logged
     * @param msg the message string to be logged
     *
     */
    public void trace(Throwable throwable, Supplier<String> msg) {
        LogLevel.TRACE.log(delegate, msg, throwable);
    }

    /**
     * Log a message at the trace level.
     *
     * @param msg the message string to be logged
     * @param throwable to be logged
     *
     */
    public void trace(String msg, Throwable throwable) {
        LogLevel.TRACE.handleActualLog(delegate, msg, throwable);
    }

    /**
     * Log a message at the trace level.
     *
     * @param throwable to be logged
     * @param template to be used for formatting, see class-documentation for details on formatting
     * @param parameter to be used for replacing the placeholder
     *
     */
    public void trace(Throwable throwable, String template, Object... parameter) {
        LogLevel.TRACE.log(delegate, throwable, template, parameter);
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
     * @return {@code true} if this CuiLogger is enabled for the debug level,
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
        LogLevel.DEBUG.handleActualLog(delegate, msg, null);
    }

    /**
     * Log a message at the debug level.
     *
     * @param msg the message string to be logged
     * @param throwable to be logged
     *
     */
    public void debug(String msg, Throwable throwable) {
        LogLevel.DEBUG.handleActualLog(delegate, msg, throwable);
    }

    /**
     * Log a message at the debug level.
     *
     * @param msg the message string to be logged
     *
     */
    public void debug(Supplier<String> msg) {
        LogLevel.DEBUG.log(delegate, msg, null);
    }

    /**
     * Log a message at the debug level.
     *
     * @param throwable to be logged
     * @param msg the message string to be logged
     *
     */
    public void debug(Throwable throwable, Supplier<String> msg) {
        LogLevel.DEBUG.log(delegate, msg, throwable);
    }

    /**
     * Log a message at the debug level.
     *
     * @param throwable to be logged
     * @param template to be used for formatting, see class-documentation for details on formatting
     * @param parameter to be used for replacing the placeholder
     *
     */
    public void debug(Throwable throwable, String template, Object... parameter) {
        LogLevel.DEBUG.log(delegate, throwable, template, parameter);
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
     * @return {@code true} if this CuiLogger is enabled for the info level,
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
        LogLevel.INFO.handleActualLog(delegate, msg, null);
    }

    /**
     * Log a message at the info level.
     *
     * @param msg the message string to be logged
     * @param throwable to be logged
     *
     */
    public void info(String msg, Throwable throwable) {
        LogLevel.INFO.handleActualLog(delegate, msg, throwable);
    }

    /**
     * Log a message at the info level.
     *
     * @param msg the message string to be logged
     *
     */
    public void info(Supplier<String> msg) {
        LogLevel.INFO.log(delegate, msg, null);
    }

    /**
     * Log a message at the info level.
     *
     * @param throwable to be logged
     * @param msg the message string to be logged
     *
     */
    public void info(Throwable throwable, Supplier<String> msg) {
        LogLevel.INFO.log(delegate, msg, throwable);
    }

    /**
     * Log a message at the info level.
     *
     * @param throwable to be logged
     * @param template to be used for formatting, see class-documentation for details on formatting
     * @param parameter to be used for replacing the placeholder
     *
     */
    public void info(Throwable throwable, String template, Object... parameter) {
        LogLevel.INFO.log(delegate, throwable, template, parameter);
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
     * @return {@code true} if this CuiLogger is enabled for the warn level,
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
        LogLevel.WARN.handleActualLog(delegate, msg, null);
    }

    /**
     * Log a message at the warn level.
     *
     * @param msg the message string to be logged
     * @param throwable to be logged
     *
     */
    public void warn(String msg, Throwable throwable) {
        LogLevel.WARN.handleActualLog(delegate, msg, throwable);
    }

    /**
     * Log a message at the warn level.
     *
     * @param msg the message string to be logged
     *
     */
    public void warn(Supplier<String> msg) {
        LogLevel.WARN.log(delegate, msg, null);
    }

    /**
     * Log a message at the warn level.
     *
     * @param throwable to be logged
     * @param msg the message string to be logged
     *
     */
    public void warn(Throwable throwable, Supplier<String> msg) {
        LogLevel.WARN.log(delegate, msg, throwable);
    }

    /**
     * Log a message at the warn level.
     *
     * @param throwable to be logged
     * @param template to be used for formatting, see class-documentation for details on formatting
     * @param parameter to be used for replacing the placeholder
     *
     */
    public void warn(Throwable throwable, String template, Object... parameter) {
        LogLevel.WARN.log(delegate, throwable, template, parameter);
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
     * @return {@code true} if this CuiLogger is enabled for the error level,
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
        LogLevel.ERROR.handleActualLog(delegate, msg, null);
    }

    /**
     * Log a message at the error level.
     *
     * @param msg the message string to be logged
     * @param throwable to be logged
     *
     */
    public void error(String msg, Throwable throwable) {
        LogLevel.ERROR.handleActualLog(delegate, msg, throwable);
    }

    /**
     * Log a message at the error level.
     *
     * @param msg the message string to be logged
     *
     */
    public void error(Supplier<String> msg) {
        LogLevel.ERROR.log(delegate, msg, null);
    }

    /**
     * Log a message at the error level.
     *
     * @param throwable to be logged
     * @param msg the message string to be logged
     *
     */
    public void error(Throwable throwable, Supplier<String> msg) {
        LogLevel.ERROR.log(delegate, msg, throwable);
    }

    /**
     * Log a message at the error level.
     *
     * @param throwable to be logged
     * @param template to be used for formatting, see class-documentation for details on formatting
     * @param parameter to be used for replacing the placeholder
     *
     */
    public void error(Throwable throwable, String template, Object... parameter) {
        LogLevel.ERROR.log(delegate, throwable, template, parameter);
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

    Logger getWrapped() {
        return delegate;
    }

    /**
     * @return the name / class of the underlying logger
     */
    public String getName() {
        return delegate.getName();
    }

    /**
     * @return CUI log level derived from JUL log level.
     *         E.g. FINEST(300) matches TRACE(400), CONFIG(700) matches DEBUG(500), ALL matches TRACE.
     */
    public LogLevel getLogLevel() {
        return LogLevel.from(delegate.getLevel());
    }

}
