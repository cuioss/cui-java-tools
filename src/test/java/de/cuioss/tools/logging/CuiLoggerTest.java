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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Test class for {@link CuiLogger} ensuring proper logging behavior and
 * integration with {@link LogRecord} and {@link LogRecordModel}.
 */
// cui-rewrite:disable
@DisplayName("CuiLogger Tests")
class CuiLoggerTest {

    private static final String TRACE = "trace";
    private static final String DEBUG = "debug";
    private static final String INFO = "info";
    private static final String WARN = "warn";
    private static final String ERROR = "error";

    private static final String SLF4J_TEMPLATE = "some '{}' log {} formatted";
    private static final String STRING_TEMPLATE = "some '%s' log %s formatted";
    private static final String TEMPLATE_RESULT = "some '1' log 2 formatted";

    private static final Supplier<String> EXPLODER = () -> {
        throw new IllegalArgumentException("Should not be called");
    };

    private CuiLogger underTest;
    private TestLogHandler handler;
    private Throwable throwable;

    @BeforeEach
    void before() {
        underTest = new CuiLogger(CuiLogger.class);
        handler = new TestLogHandler();
        underTest.getWrapped().setUseParentHandlers(false);
        underTest.getWrapped().addHandler(handler);
        underTest.getWrapped().setLevel(Level.ALL);
        throwable = new RuntimeException("Test exception");
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {
        @Test
        @DisplayName("Should create logger with Class parameter")
        void shouldCreateLoggerWithClass() {
            var logger = new CuiLogger(String.class);
            assertNotNull(logger);
            assertEquals("java.lang.String", logger.getWrapped().getName());
        }

        @Test
        @DisplayName("Should create logger with String parameter")
        void shouldCreateLoggerWithString() {
            var logger = new CuiLogger("test.logger.name");
            assertNotNull(logger);
            assertEquals("test.logger.name", logger.getWrapped().getName());
        }

        @Test
        @DisplayName("Should reject null Class parameter")
        void shouldRejectNullClass() {
            assertThrows(NullPointerException.class,
                    () -> new CuiLogger((Class<?>) null),
                    "Should throw NullPointerException for null class");
        }

        @Test
        @DisplayName("Should reject null String parameter")
        void shouldRejectNullString() {
            assertThrows(NullPointerException.class,
                    () -> new CuiLogger((String) null),
                    "Should throw NullPointerException for null name");
        }

        @Test
        @DisplayName("Should return log level from wrapped logger")
        void shouldReturnLogLevel() {
            underTest.getWrapped().setLevel(Level.WARNING);
            assertEquals(LogLevel.WARN, underTest.getLogLevel());

            underTest.getWrapped().setLevel(Level.INFO);
            assertEquals(LogLevel.INFO, underTest.getLogLevel());
        }
    }

    @Nested
    @DisplayName("Log Level Tests")
    class LogLevelTests {
        @Test
        void shouldHandleLogGuard() {
            var reference = Logger.getLogger(CuiLogger.class.getName());

            assertEquals(underTest.isTraceEnabled(), reference.isLoggable(Level.FINER));
            assertEquals(underTest.isDebugEnabled(), reference.isLoggable(Level.FINE));
            assertEquals(underTest.isInfoEnabled(), reference.isLoggable(Level.INFO));
            assertEquals(underTest.isWarnEnabled(), reference.isLoggable(Level.WARNING));
            assertEquals(underTest.isErrorEnabled(), reference.isLoggable(Level.SEVERE));
        }

        @ParameterizedTest(name = "Level {0} should handle simple logging")
        @MethodSource("de.cuioss.tools.logging.CuiLoggerTest#provideLogLevels")
        void shouldHandleSimpleLogging(Level level, String message, LogMethod logMethod) {
            logMethod.log(underTest, message);
            handler.assertMessagePresent(message, level);
        }

        @ParameterizedTest(name = "Level {0} should handle logging with throwable")
        @MethodSource("de.cuioss.tools.logging.CuiLoggerTest#provideLogLevels")
        void shouldHandleLoggingWithThrowable(Level level, String message, LogMethod logMethod) {
            logMethod.log(underTest, message, throwable);
            handler.assertMessagePresent(message, level, throwable);
        }

        @ParameterizedTest(name = "Level {0} should handle supplier logging")
        @MethodSource("de.cuioss.tools.logging.CuiLoggerTest#provideLogLevels")
        void shouldHandleSupplierLogging(Level level, String message, LogMethod logMethod) {
            logMethod.logSupplier(underTest, () -> message);
            handler.assertMessagePresent(message, level);
        }
    }

    @Nested
    @DisplayName("Message Formatting Tests")
    class MessageFormattingTests {
        @ParameterizedTest(name = "Level {0} should handle slf4j style formatting")
        @MethodSource("de.cuioss.tools.logging.CuiLoggerTest#provideLogLevels")
        void shouldHandleSlf4jFormatting(Level level, String message, LogMethod logMethod) {
            logMethod.logFormat(underTest, SLF4J_TEMPLATE, "1", "2");
            handler.assertMessagePresent(TEMPLATE_RESULT, level);
        }

        @ParameterizedTest(name = "Level {0} should handle string style formatting")
        @MethodSource("de.cuioss.tools.logging.CuiLoggerTest#provideLogLevels")
        void shouldHandleStringFormatting(Level level, String message, LogMethod logMethod) {
            logMethod.logFormat(underTest, STRING_TEMPLATE, "1", "2");
            handler.assertMessagePresent(TEMPLATE_RESULT, level);
        }
    }

    @Nested
    @DisplayName("Error Handling Tests")
    class ErrorHandlingTests {
        @Test
        void shouldHandleNamedLogger() {
            assertFalse(CuiLoggerFactory.getLogger(this.getClass()).isDebugEnabled());
            assertTrue(CuiLoggerFactory.getLogger().getName().startsWith("de.cuioss.tools.logging.CuiLoggerTest"));
        }

        @Test
        void supplierShouldOnlyBeCalledIfTheLoggerIsConfigured() {
            assertThrows(IllegalArgumentException.class, () -> underTest.trace(EXPLODER));
            underTest.getWrapped().setLevel(Level.FINE);
            underTest.trace(EXPLODER);

            assertThrows(IllegalArgumentException.class, () -> underTest.debug(EXPLODER));
            underTest.getWrapped().setLevel(Level.INFO);
            underTest.debug(EXPLODER);

            assertThrows(IllegalArgumentException.class, () -> underTest.info(EXPLODER));
            underTest.getWrapped().setLevel(Level.WARNING);
            underTest.info(EXPLODER);

            assertThrows(IllegalArgumentException.class, () -> underTest.warn(EXPLODER));
            underTest.getWrapped().setLevel(Level.SEVERE);
            underTest.warn(EXPLODER);

            assertThrows(IllegalArgumentException.class, () -> underTest.error(EXPLODER));
            underTest.getWrapped().setLevel(Level.OFF);
            underTest.error(EXPLODER);
        }
    }

    @Nested
    @DisplayName("Enhanced Logging Tests")
    class EnhancedLoggingTests {

        private static final String TEST_MESSAGE = "test message";
        private static final String FORMATTED_MESSAGE = "formatted message: {}";
        private static final String PARAMETER = "param";
        private static final RuntimeException TEST_EXCEPTION = new RuntimeException("test exception");

        @Test
        void shouldHandleTraceLevel() {
            // Given trace is enabled
            assumeTrue(underTest.isTraceEnabled(), "Trace logging must be enabled for this test");

            // When/Then - no assertions needed as per logging rules
            underTest.trace(TEST_MESSAGE);
            underTest.trace(TEST_EXCEPTION, TEST_MESSAGE);
            underTest.trace(() -> TEST_MESSAGE);
            underTest.trace(TEST_EXCEPTION, () -> TEST_MESSAGE);
            underTest.trace(FORMATTED_MESSAGE, PARAMETER);
            assertDoesNotThrow(() -> underTest.trace(TEST_EXCEPTION, FORMATTED_MESSAGE, PARAMETER));
        }

        @Test
        void shouldHandleDebugLevel() {
            // Given debug is enabled
            assumeTrue(underTest.isDebugEnabled(), "Debug logging must be enabled for this test");

            // When/Then - no assertions needed as per logging rules
            underTest.debug(TEST_MESSAGE);
            underTest.debug(TEST_EXCEPTION, TEST_MESSAGE);
            underTest.debug(() -> TEST_MESSAGE);
            underTest.debug(TEST_EXCEPTION, () -> TEST_MESSAGE);
            underTest.debug(FORMATTED_MESSAGE, PARAMETER);
            assertDoesNotThrow(() -> underTest.debug(TEST_EXCEPTION, FORMATTED_MESSAGE, PARAMETER));
        }

        @Test
        void shouldHandleInfoLevel() {
            // Given info is enabled
            assumeTrue(underTest.isInfoEnabled(), "Info logging must be enabled for this test");

            // When/Then - no assertions needed as per logging rules
            underTest.info(TEST_MESSAGE);
            underTest.info(TEST_EXCEPTION, TEST_MESSAGE);
            underTest.info(() -> TEST_MESSAGE);
            underTest.info(TEST_EXCEPTION, () -> TEST_MESSAGE);
            underTest.info(FORMATTED_MESSAGE, PARAMETER);
            assertDoesNotThrow(() -> underTest.info(TEST_EXCEPTION, FORMATTED_MESSAGE, PARAMETER));
        }

        @Test
        void shouldHandleWarnLevel() {
            // Given warn is enabled
            assumeTrue(underTest.isWarnEnabled(), "Warn logging must be enabled for this test");

            // When/Then - no assertions needed as per logging rules
            underTest.warn(TEST_MESSAGE);
            underTest.warn(TEST_EXCEPTION, TEST_MESSAGE);
            underTest.warn(() -> TEST_MESSAGE);
            underTest.warn(TEST_EXCEPTION, () -> TEST_MESSAGE);
            underTest.warn(FORMATTED_MESSAGE, PARAMETER);
            assertDoesNotThrow(() -> underTest.warn(TEST_EXCEPTION, FORMATTED_MESSAGE, PARAMETER));
        }

        @Test
        void shouldHandleErrorLevel() {
            // Given error is enabled
            assumeTrue(underTest.isErrorEnabled(), "Error logging must be enabled for this test");

            // When/Then - no assertions needed as per logging rules
            underTest.error(TEST_MESSAGE);
            underTest.error(TEST_EXCEPTION, TEST_MESSAGE);
            underTest.error(() -> TEST_MESSAGE);
            underTest.error(TEST_EXCEPTION, () -> TEST_MESSAGE);
            underTest.error(FORMATTED_MESSAGE, PARAMETER);
            assertDoesNotThrow(() -> underTest.error(TEST_EXCEPTION, FORMATTED_MESSAGE, PARAMETER));
        }

        @Test
        void shouldHandleStructuredLogging() {
            // Given
            var logRecord = LogRecordModel.builder()
                    .identifier(100)
                    .prefix("TEST")
                    .template("Structured log: {}")
                    .build();

            // When/Then
            underTest.info(logRecord.format("test data"));
            assertDoesNotThrow(() -> underTest.error(TEST_EXCEPTION, logRecord.format("error data")));
        }

        @Test
        void shouldHandleMultipleParameters() {
            // Given
            var template = "Value1: {}, Value2: {}, Value3: {}";
            var param1 = "first";
            var param2 = "second";
            var param3 = "third";

            // When/Then
            underTest.info(template, param1, param2, param3);
            assertDoesNotThrow(() -> underTest.error(TEST_EXCEPTION, template, param1, param2, param3));
        }

        @Test
        void shouldHandleNullParameters() {
            // When/Then
            underTest.info(FORMATTED_MESSAGE, (Object) null);
            assertDoesNotThrow(() -> underTest.error(TEST_EXCEPTION, FORMATTED_MESSAGE, (Object) null));
        }

        @Test
        void shouldHandleSuppliers() {
            // Given
            Supplier<String> messageSupplier = () -> "Computed message";

            // When/Then
            underTest.info(messageSupplier);
            assertDoesNotThrow(() -> underTest.error(TEST_EXCEPTION, messageSupplier));
        }
    }

    @Nested
    @DisplayName("LogRecord Integration Tests")
    class LogRecordIntegrationTests {

        private LogRecord testLogRecord;
        private LogRecord logRecordWithParams;

        @BeforeEach
        void setUp() {
            testLogRecord = LogRecordModel.builder()
                    .identifier(100)
                    .prefix("TEST")
                    .template("Simple log message")
                    .build();

            logRecordWithParams = LogRecordModel.builder()
                    .identifier(200)
                    .prefix("TEST")
                    .template("Formatted log: {}, {}")
                    .build();
        }

        @Test
        @DisplayName("Should handle INFO level LogRecord without parameters")
        void shouldHandleInfoLogRecordWithoutParams() {
            assumeTrue(underTest.isInfoEnabled(), "Info logging must be enabled");

            underTest.info(testLogRecord);

            handler.assertMessagePresent("TEST-100: Simple log message", Level.INFO);
        }

        @Test
        @DisplayName("Should handle INFO level LogRecord with parameters")
        void shouldHandleInfoLogRecordWithParams() {
            assumeTrue(underTest.isInfoEnabled(), "Info logging must be enabled");

            underTest.info(logRecordWithParams, "value1", "value2");

            handler.assertMessagePresent("TEST-200: Formatted log: value1, value2", Level.INFO);
        }

        @Test
        @DisplayName("Should handle INFO level LogRecord with throwable")
        void shouldHandleInfoLogRecordWithThrowable() {
            assumeTrue(underTest.isInfoEnabled(), "Info logging must be enabled");

            underTest.info(throwable, testLogRecord);

            handler.assertMessagePresent("TEST-100: Simple log message", Level.INFO, throwable);
        }

        @Test
        @DisplayName("Should handle INFO level LogRecord with throwable and parameters")
        void shouldHandleInfoLogRecordWithThrowableAndParams() {
            assumeTrue(underTest.isInfoEnabled(), "Info logging must be enabled");

            underTest.info(throwable, logRecordWithParams, "error1", "error2");

            handler.assertMessagePresent("TEST-200: Formatted log: error1, error2", Level.INFO, throwable);
        }

        @Test
        @DisplayName("Should handle WARN level LogRecord without parameters")
        void shouldHandleWarnLogRecordWithoutParams() {
            assumeTrue(underTest.isWarnEnabled(), "Warn logging must be enabled");

            underTest.warn(testLogRecord);

            handler.assertMessagePresent("TEST-100: Simple log message", Level.WARNING);
        }

        @Test
        @DisplayName("Should handle WARN level LogRecord with parameters")
        void shouldHandleWarnLogRecordWithParams() {
            assumeTrue(underTest.isWarnEnabled(), "Warn logging must be enabled");

            underTest.warn(logRecordWithParams, "value1", "value2");

            handler.assertMessagePresent("TEST-200: Formatted log: value1, value2", Level.WARNING);
        }

        @Test
        @DisplayName("Should handle WARN level LogRecord with throwable")
        void shouldHandleWarnLogRecordWithThrowable() {
            assumeTrue(underTest.isWarnEnabled(), "Warn logging must be enabled");

            underTest.warn(throwable, testLogRecord);

            handler.assertMessagePresent("TEST-100: Simple log message", Level.WARNING, throwable);
        }

        @Test
        @DisplayName("Should handle WARN level LogRecord with throwable and parameters")
        void shouldHandleWarnLogRecordWithThrowableAndParams() {
            assumeTrue(underTest.isWarnEnabled(), "Warn logging must be enabled");

            underTest.warn(throwable, logRecordWithParams, "warn1", "warn2");

            handler.assertMessagePresent("TEST-200: Formatted log: warn1, warn2", Level.WARNING, throwable);
        }

        @Test
        @DisplayName("Should handle ERROR level LogRecord without parameters")
        void shouldHandleErrorLogRecordWithoutParams() {
            assumeTrue(underTest.isErrorEnabled(), "Error logging must be enabled");

            underTest.error(testLogRecord);

            handler.assertMessagePresent("TEST-100: Simple log message", Level.SEVERE);
        }

        @Test
        @DisplayName("Should handle ERROR level LogRecord with parameters")
        void shouldHandleErrorLogRecordWithParams() {
            assumeTrue(underTest.isErrorEnabled(), "Error logging must be enabled");

            underTest.error(logRecordWithParams, "value1", "value2");

            handler.assertMessagePresent("TEST-200: Formatted log: value1, value2", Level.SEVERE);
        }

        @Test
        @DisplayName("Should handle ERROR level LogRecord with throwable")
        void shouldHandleErrorLogRecordWithThrowable() {
            assumeTrue(underTest.isErrorEnabled(), "Error logging must be enabled");

            underTest.error(throwable, testLogRecord);

            handler.assertMessagePresent("TEST-100: Simple log message", Level.SEVERE, throwable);
        }

        @Test
        @DisplayName("Should handle ERROR level LogRecord with throwable and parameters")
        void shouldHandleErrorLogRecordWithThrowableAndParams() {
            assumeTrue(underTest.isErrorEnabled(), "Error logging must be enabled");

            underTest.error(throwable, logRecordWithParams, "error1", "error2");

            handler.assertMessagePresent("TEST-200: Formatted log: error1, error2", Level.SEVERE, throwable);
        }

        @Test
        @DisplayName("Should only format LogRecord when log level is enabled")
        void shouldLazilyFormatLogRecord() {
            // Given a log record that would fail if formatted
            LogRecord failingRecord = new LogRecord() {
                @Override
                public String getPrefix() {
                    return "FAIL";
                }

                @Override
                public Integer getIdentifier() {
                    return 999;
                }

                @Override
                public String getTemplate() {
                    return "Should not be called";
                }

                @Override
                public Supplier<String> supplier(Object... parameter) {
                    throw new UnsupportedOperationException();
                }

                @Override
                public String format(Object... parameter) {
                    throw new IllegalStateException("Format should not be called when level is disabled");
                }

                @Override
                public String resolveIdentifierString() {
                    return "FAIL-999";
                }
            };

            // When logging is disabled
            underTest.getWrapped().setLevel(Level.OFF);

            // Then no exception should be thrown
            assertDoesNotThrow(() -> underTest.info(failingRecord));
            assertDoesNotThrow(() -> underTest.info(failingRecord, "param"));
            assertDoesNotThrow(() -> underTest.info(throwable, failingRecord));
            assertDoesNotThrow(() -> underTest.info(throwable, failingRecord, "param"));
        }

        @Test
        @DisplayName("Should handle optimized String + Throwable methods")
        void shouldHandleOptimizedStringThrowableMethods() {
            String message = "Optimized message";

            // TRACE level
            assumeTrue(underTest.isTraceEnabled(), "Trace logging must be enabled");
            underTest.trace(throwable, message);
            handler.assertMessagePresent(message, Level.FINER, throwable);

            handler.clearRecords();

            // DEBUG level
            assumeTrue(underTest.isDebugEnabled(), "Debug logging must be enabled");
            underTest.debug(throwable, message);
            handler.assertMessagePresent(message, Level.FINE, throwable);

            handler.clearRecords();

            // INFO level
            assumeTrue(underTest.isInfoEnabled(), "Info logging must be enabled");
            underTest.info(throwable, message);
            handler.assertMessagePresent(message, Level.INFO, throwable);

            handler.clearRecords();

            // WARN level
            assumeTrue(underTest.isWarnEnabled(), "Warn logging must be enabled");
            underTest.warn(throwable, message);
            handler.assertMessagePresent(message, Level.WARNING, throwable);

            handler.clearRecords();

            // ERROR level
            assumeTrue(underTest.isErrorEnabled(), "Error logging must be enabled");
            underTest.error(throwable, message);
            handler.assertMessagePresent(message, Level.SEVERE, throwable);
        }
    }

    @SuppressWarnings("java:S1144") // owolff: used by tests using MethodSource
    private static Stream<Arguments> provideLogLevels() {
        return Stream.of(
                Arguments.of(Level.FINER, TRACE, new LogMethod() {
                    @Override
                    public void log(CuiLogger logger, String msg) {
                        logger.trace(msg);
                    }

                    @Override
                    public void log(CuiLogger logger, String msg, Throwable t) {
                        logger.trace(msg, t);
                    }

                    @Override
                    public void logSupplier(CuiLogger logger, Supplier<String> supplier) {
                        logger.trace(supplier);
                    }

                    @Override
                    public void logFormat(CuiLogger logger, String template, Object... args) {
                        logger.trace(template, args);
                    }
                }),
                Arguments.of(Level.FINE, DEBUG, new LogMethod() {
                    @Override
                    public void log(CuiLogger logger, String msg) {
                        logger.debug(msg);
                    }

                    @Override
                    public void log(CuiLogger logger, String msg, Throwable t) {
                        logger.debug(msg, t);
                    }

                    @Override
                    public void logSupplier(CuiLogger logger, Supplier<String> supplier) {
                        logger.debug(supplier);
                    }

                    @Override
                    public void logFormat(CuiLogger logger, String template, Object... args) {
                        logger.debug(template, args);
                    }
                }),
                Arguments.of(Level.INFO, INFO, new LogMethod() {
                    @Override
                    public void log(CuiLogger logger, String msg) {
                        logger.info(msg);
                    }

                    @Override
                    public void log(CuiLogger logger, String msg, Throwable t) {
                        logger.info(msg, t);
                    }

                    @Override
                    public void logSupplier(CuiLogger logger, Supplier<String> supplier) {
                        logger.info(supplier);
                    }

                    @Override
                    public void logFormat(CuiLogger logger, String template, Object... args) {
                        logger.info(template, args);
                    }
                }),
                Arguments.of(Level.WARNING, WARN, new LogMethod() {
                    @Override
                    public void log(CuiLogger logger, String msg) {
                        logger.warn(msg);
                    }

                    @Override
                    public void log(CuiLogger logger, String msg, Throwable t) {
                        logger.warn(msg, t);
                    }

                    @Override
                    public void logSupplier(CuiLogger logger, Supplier<String> supplier) {
                        logger.warn(supplier);
                    }

                    @Override
                    public void logFormat(CuiLogger logger, String template, Object... args) {
                        logger.warn(template, args);
                    }
                }),
                Arguments.of(Level.SEVERE, ERROR, new LogMethod() {
                    @Override
                    public void log(CuiLogger logger, String msg) {
                        logger.error(msg);
                    }

                    @Override
                    public void log(CuiLogger logger, String msg, Throwable t) {
                        logger.error(msg, t);
                    }

                    @Override
                    public void logSupplier(CuiLogger logger, Supplier<String> supplier) {
                        logger.error(supplier);
                    }

                    @Override
                    public void logFormat(CuiLogger logger, String template, Object... args) {
                        logger.error(template, args);
                    }
                })
        );
    }

    private interface LogMethod {
        void log(CuiLogger logger, String msg);

        void log(CuiLogger logger, String msg, Throwable t);

        void logSupplier(CuiLogger logger, Supplier<String> supplier);

        void logFormat(CuiLogger logger, String template, Object... args);
    }
}
