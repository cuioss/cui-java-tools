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

import java.util.function.Supplier;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import static de.cuioss.tools.string.MoreStrings.nullToEmpty;
import static java.util.Objects.requireNonNull;

/**
 * A wrapper around java-util {@link Logger} that provides enhanced logging capabilities
 * with a focus on performance, type safety, and ease of use.
 *
 * <h2>Key Features</h2>
 * <ul>
 *   <li>Support for both SLF4J-style ({}) and printf-style (%s) placeholders</li>
 *   <li>Lazy message evaluation using {@link Supplier}</li>
 *   <li>Built-in code guard optimization</li>
 *   <li>Exception-first parameter convention</li>
 *   <li>Integration with {@link LogRecord} for structured logging</li>
 * </ul>
 *
 * <h2>Usage Examples</h2>
 *
 * <h3>1. Basic Logging</h3>
 * <pre>
 * public class UserService {
 *     private static final CuiLogger log = new CuiLogger(UserService.class);
 *
 *     public void createUser(String username) {
 *         log.info("Creating new user: {}", username);
 *
 *         try {
 *             // ... user creation logic
 *             log.debug("User {} created successfully", username);
 *         } catch (Exception e) {
 *             log.error(e, "Failed to create user: {}", username);
 *         }
 *     }
 * }
 * </pre>
 *
 * <h3>2. Performance Optimization with Suppliers</h3>
 * <pre>
 * public class PerformanceService {
 *     private static final CuiLogger log = new CuiLogger(PerformanceService.class);
 *
 *     public void processData(List&lt;String&gt; items) {
 *         // Message will only be constructed if debug is enabled
 *         log.debug(() -> String.format("Processing %d items: %s",
 *             items.size(),
 *             items.stream().limit(5).collect(Collectors.joining(", "))));
 *
 *         // ... processing logic
 *     }
 * }
 * </pre>
 *
 * <h3>3. Exception Handling with Context</h3>
 * <pre>
 * public class DataProcessor {
 *     private static final CuiLogger log = new CuiLogger(DataProcessor.class);
 *
 *     public void process(String filename, Map&lt;String, Object&gt; data) {
 *         try {
 *             // ... processing logic
 *         } catch (IOException e) {
 *             // Exception is always the first parameter
 *             log.error(e, "Failed to process file '{}' with {} entries",
 *                 filename, data.size());
 *             throw new ProcessingException("Processing failed", e);
 *         }
 *     }
 * }
 * </pre>
 *
 * <h3>4. Integration with LogRecord</h3>
 * <pre>
 * public class ConfigService {
 *     private static final CuiLogger log = new CuiLogger(ConfigService.class);
 *     private static final LogRecord CONFIG_UPDATED = LogRecordModel.builder()
 *         .prefix("CONFIG")
 *         .identifier(3001)
 *         .message("Configuration updated - Key: {}, Value: {}")
 *         .build();
 *
 *     public void updateConfig(String key, String value) {
 *         log.info(CONFIG_UPDATED.format(key, value));
 *     }
 * }
 * </pre>
 *
 * <h3>5. Different Log Levels and Guards</h3>
 * <pre>
 * public class SecurityService {
 *     private static final CuiLogger log = new CuiLogger(SecurityService.class);
 *
 *     public void authenticate(String username) {
 *         // Trace level for detailed debugging
 *         log.trace("Authentication attempt for user: {}", username);
 *
 *         // Debug level for development information
 *         if (log.isDebugEnabled()) {
 *             log.debug(() -> "Detailed auth context: " + getAuthContext());
 *         }
 *
 *         try {
 *             // Info level for normal operation
 *             log.info("User {} authenticated successfully", username);
 *         } catch (AuthException e) {
 *             // Warn level for handled issues
 *             log.warn(e, "Authentication failed for user: {}", username);
 *         } catch (Exception e) {
 *             // Error level for serious issues
 *             log.error(e, "Unexpected error during authentication");
 *         }
 *     }
 * }
 * </pre>
 *
 * <h2>Best Practices</h2>
 * <ul>
 *   <li>Always declare logger as private static final</li>
 *   <li>Use appropriate log levels based on message importance</li>
 *   <li>Place exceptions as the first parameter in error logging</li>
 *   <li>Use suppliers for expensive message construction</li>
 *   <li>Check isEnabled() before complex message construction</li>
 *   <li>Prefer {} placeholder over %s for better readability</li>
 *   <li>Include relevant context in log messages</li>
 * </ul>
 *
 * @author Oliver Wolff
 * @see LogRecord
 * @see LogRecordModel
 * @see java.util.logging.Logger
 */
@SuppressWarnings("javaarchitecture:S7091") // Owolff: The only way to fix the cycle-warning it to replicate code.
// Therefore, suppressed
public class CuiLogger {

    private final Logger delegate;

    static final Pattern SLF4J_PATTERN = Pattern.compile(Pattern.quote("{}"));

    /**
     * @param clazz to be used for acquiring a concrete {@link Logger} instance.
     *              Must not be null
     */
    public CuiLogger(Class<?> clazz) {
        requireNonNull(clazz);
        delegate = Logger.getLogger(clazz.getName());
    }

    /**
     * @param name to be used for acquiring a concrete {@link Logger} instance. Must
     *             not be null
     */
    public CuiLogger(String name) {
        requireNonNull(nullToEmpty(name));
        delegate = Logger.getLogger(name);
    }

    /**
     * Is the logger instance enabled for the trace level?
     *
     * @return {@code true} if this CuiLogger is enabled for the trace level, false
     * otherwise.
     */
    public boolean isTraceEnabled() {
        return LogLevel.TRACE.isEnabled(delegate);
    }

    /**
     * Log a message at the trace level.
     *
     * @param msg the message string to be logged
     */
    public void trace(String msg) {
        LogLevel.TRACE.handleActualLog(delegate, msg, null);
    }

    /**
     * Log a message at the trace level.
     *
     * @param msg the message string to be logged
     */
    public void trace(Supplier<String> msg) {
        LogLevel.TRACE.log(delegate, msg, null);
    }

    /**
     * Log a message at the trace level.
     *
     * @param throwable to be logged
     * @param msg       the message string to be logged
     */
    public void trace(Throwable throwable, Supplier<String> msg) {
        LogLevel.TRACE.log(delegate, msg, throwable);
    }

    /**
     * Log a message at the trace level.
     *
     * @param msg       the message string to be logged
     * @param throwable to be logged
     */
    public void trace(String msg, Throwable throwable) {
        LogLevel.TRACE.handleActualLog(delegate, msg, throwable);
    }

    /**
     * Log a message at the trace level.
     *
     * @param throwable to be logged
     * @param template  to be used for formatting, see class-documentation for
     *                  details on formatting
     * @param parameter to be used for replacing the placeholder
     */
    public void trace(Throwable throwable, String template, Object... parameter) {
        LogLevel.TRACE.log(delegate, throwable, template, parameter);
    }

    /**
     * Log a message at the trace level.
     *
     * @param template  to be used for formatting, see class-documentation for
     *                  details on formatting
     * @param parameter to be used for replacing the placeholder
     */
    public void trace(String template, Object... parameter) {
        LogLevel.TRACE.log(delegate, template, parameter);
    }

    /**
     * Is the logger instance enabled for the debug level?
     *
     * @return {@code true} if this CuiLogger is enabled for the debug level, false
     * otherwise.
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
     * @param msg       the message string to be logged
     * @param throwable to be logged
     */
    public void debug(String msg, Throwable throwable) {
        LogLevel.DEBUG.handleActualLog(delegate, msg, throwable);
    }

    /**
     * Log a message at the debug level.
     *
     * @param msg the message string to be logged
     */
    public void debug(Supplier<String> msg) {
        LogLevel.DEBUG.log(delegate, msg, null);
    }

    /**
     * Log a message at the debug level.
     *
     * @param throwable to be logged
     * @param msg       the message string to be logged
     */
    public void debug(Throwable throwable, Supplier<String> msg) {
        LogLevel.DEBUG.log(delegate, msg, throwable);
    }

    /**
     * Log a message at the debug level.
     *
     * @param throwable to be logged
     * @param template  to be used for formatting, see class-documentation for
     *                  details on formatting
     * @param parameter to be used for replacing the placeholder
     */
    public void debug(Throwable throwable, String template, Object... parameter) {
        LogLevel.DEBUG.log(delegate, throwable, template, parameter);
    }

    /**
     * Log a message at the debug level.
     *
     * @param template  to be used for formatting, see class-documentation for
     *                  details on formatting
     * @param parameter to be used for replacing the placeholder
     */
    public void debug(String template, Object... parameter) {
        LogLevel.DEBUG.log(delegate, template, parameter);
    }

    /**
     * Is the logger instance enabled for the info level?
     *
     * @return {@code true} if this CuiLogger is enabled for the info level, false
     * otherwise.
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
     * @param msg       the message string to be logged
     * @param throwable to be logged
     */
    public void info(String msg, Throwable throwable) {
        LogLevel.INFO.handleActualLog(delegate, msg, throwable);
    }

    /**
     * Log a message at the info level.
     *
     * @param msg the message string to be logged
     */
    public void info(Supplier<String> msg) {
        LogLevel.INFO.log(delegate, msg, null);
    }

    /**
     * Log a message at the info level.
     *
     * @param throwable to be logged
     * @param msg       the message string to be logged
     */
    public void info(Throwable throwable, Supplier<String> msg) {
        LogLevel.INFO.log(delegate, msg, throwable);
    }

    /**
     * Log a message at the info level.
     *
     * @param throwable to be logged
     * @param template  to be used for formatting, see class-documentation for
     *                  details on formatting
     * @param parameter to be used for replacing the placeholder
     */
    public void info(Throwable throwable, String template, Object... parameter) {
        LogLevel.INFO.log(delegate, throwable, template, parameter);
    }

    /**
     * Log a message at the info level.
     *
     * @param template  to be used for formatting, see class-documentation for
     *                  details on formatting
     * @param parameter to be used for replacing the placeholder
     */
    public void info(String template, Object... parameter) {
        LogLevel.INFO.log(delegate, template, parameter);
    }

    /**
     * Is the logger instance enabled for the warn level?
     *
     * @return {@code true} if this CuiLogger is enabled for the warn level, false
     * otherwise.
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
     * @param msg       the message string to be logged
     * @param throwable to be logged
     */
    public void warn(String msg, Throwable throwable) {
        LogLevel.WARN.handleActualLog(delegate, msg, throwable);
    }

    /**
     * Log a message at the warn level.
     *
     * @param msg the message string to be logged
     */
    public void warn(Supplier<String> msg) {
        LogLevel.WARN.log(delegate, msg, null);
    }

    /**
     * Log a message at the warn level.
     *
     * @param throwable to be logged
     * @param msg       the message string to be logged
     */
    public void warn(Throwable throwable, Supplier<String> msg) {
        LogLevel.WARN.log(delegate, msg, throwable);
    }

    /**
     * Log a message at the warn level.
     *
     * @param throwable to be logged
     * @param template  to be used for formatting, see class-documentation for
     *                  details on formatting
     * @param parameter to be used for replacing the placeholder
     */
    public void warn(Throwable throwable, String template, Object... parameter) {
        LogLevel.WARN.log(delegate, throwable, template, parameter);
    }

    /**
     * Log a message at the warn level.
     *
     * @param template  to be used for formatting, see class-documentation for
     *                  details on formatting
     * @param parameter to be used for replacing the placeholder
     */
    public void warn(String template, Object... parameter) {
        LogLevel.WARN.log(delegate, template, parameter);
    }

    /**
     * Is the logger instance enabled for the error level?
     *
     * @return {@code true} if this CuiLogger is enabled for the error level, false
     * otherwise.
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
     * @param msg       the message string to be logged
     * @param throwable to be logged
     */
    public void error(String msg, Throwable throwable) {
        LogLevel.ERROR.handleActualLog(delegate, msg, throwable);
    }

    /**
     * Log a message at the error level.
     *
     * @param msg the message string to be logged
     */
    public void error(Supplier<String> msg) {
        LogLevel.ERROR.log(delegate, msg, null);
    }

    /**
     * Log a message at the error level.
     *
     * @param throwable to be logged
     * @param msg       the message string to be logged
     */
    public void error(Throwable throwable, Supplier<String> msg) {
        LogLevel.ERROR.log(delegate, msg, throwable);
    }

    /**
     * Log a message at the error level.
     *
     * @param throwable to be logged
     * @param template  to be used for formatting, see class-documentation for
     *                  details on formatting
     * @param parameter to be used for replacing the placeholder
     */
    public void error(Throwable throwable, String template, Object... parameter) {
        LogLevel.ERROR.log(delegate, throwable, template, parameter);
    }

    /**
     * Log a message at the error level.
     *
     * @param template  to be used for formatting, see class-documentation for
     *                  details on formatting
     * @param parameter to be used for replacing the placeholder
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
     * @return CUI log level derived from JUL log level. E.g. FINEST(300) matches
     * TRACE(400), CONFIG(700) matches DEBUG(500), ALL matches TRACE.
     */
    public LogLevel getLogLevel() {
        return LogLevel.from(delegate.getLevel());
    }

}
