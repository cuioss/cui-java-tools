package de.icw.util.logging;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class LoggerTest {

    private static final String TRACE = "trace";
    private static final String DEBUG = "debug";
    private static final String INFO = "info";
    private static final String WARN = "warn";
    private static final String ERROR = "error";

    private static final String SLF4J_TEMPLATE = "some '{}' log {} formatted";
    private static final String STRING_TEMPLATE = "some '%s' log %s formatted";
    private static final String TEMPLATE_RESULT = "some '1' log 2 formatted";

    private Logger underTest;
    private LogHandler handler;

    private Throwable throwable;

    @BeforeEach
    void before() {
        underTest = new Logger(Logger.class);
        handler = new LogHandler();
        underTest.getWrapped().setUseParentHandlers(false);
        underTest.getWrapped().addHandler(handler);
        underTest.getWrapped().setLevel(Level.ALL);

        throwable = new RuntimeException();
    }

    @Test
    void shouldHandleLogGuard() {
        java.util.logging.Logger reference = java.util.logging.Logger.getLogger(Logger.class.getName());

        assertEquals(underTest.isTraceEnabled(), reference.isLoggable(Level.FINEST));
        assertEquals(underTest.isDebugEnabled(), reference.isLoggable(Level.FINE));
        assertEquals(underTest.isInfoEnabled(), reference.isLoggable(Level.INFO));
        assertEquals(underTest.isWarnEnabled(), reference.isLoggable(Level.WARNING));
        assertEquals(underTest.isErrorEnabled(), reference.isLoggable(Level.SEVERE));
    }

    @Test
    void shouldHandleNamedLogger() {
        assertFalse(new Logger("someName").isDebugEnabled());
    }

    @Test
    void shouldHandleTraceLogging() {

        underTest.trace(TRACE);
        handler.assertMessagePresent(TRACE, Level.FINEST);
        handler.clearRecords();

        underTest.trace(TRACE, throwable);
        handler.assertMessagePresent(TRACE, Level.FINEST, throwable);
        handler.clearRecords();

    }

    @Test
    void shouldHandleDebugLogging() {
        underTest.debug(DEBUG);
        handler.assertMessagePresent(DEBUG, Level.FINE);
        handler.clearRecords();

        underTest.debug(DEBUG, throwable);
        handler.assertMessagePresent(DEBUG, Level.FINE, throwable);
        handler.clearRecords();

    }

    @Test
    void shouldHandleInfoLogging() {
        underTest.info(INFO);
        handler.assertMessagePresent(INFO, Level.INFO);
        handler.clearRecords();

        underTest.info(INFO, throwable);
        handler.assertMessagePresent(INFO, Level.INFO, throwable);
        handler.clearRecords();

    }

    @Test
    void shouldHandleWarnLogging() {
        underTest.warn(WARN);
        handler.assertMessagePresent(WARN, Level.WARNING);
        handler.clearRecords();

        underTest.warn(WARN, throwable);
        handler.assertMessagePresent(WARN, Level.WARNING, throwable);
        handler.clearRecords();
    }

    @Test
    void shouldHandleErrorLogging() {
        underTest.error(ERROR);
        handler.assertMessagePresent(ERROR, Level.SEVERE);
        handler.clearRecords();

        underTest.error(ERROR, throwable);
        handler.assertMessagePresent(ERROR, Level.SEVERE, throwable);
        handler.clearRecords();
    }

    @Test
    void shouldHandleFormatting() {
        underTest.trace(SLF4J_TEMPLATE, 1, 2);
        handler.assertMessagePresent(TEMPLATE_RESULT, Level.FINEST);
        handler.clearRecords();

        underTest.trace(STRING_TEMPLATE, 1, 2);
        handler.assertMessagePresent(TEMPLATE_RESULT, Level.FINEST);
        handler.clearRecords();

        underTest.debug(STRING_TEMPLATE, 1, 2);
        handler.assertMessagePresent(TEMPLATE_RESULT, Level.FINE);
        handler.clearRecords();

        underTest.info(STRING_TEMPLATE, 1, 2);
        handler.assertMessagePresent(TEMPLATE_RESULT, Level.INFO);
        handler.clearRecords();

        underTest.warn(STRING_TEMPLATE, 1, 2);
        handler.assertMessagePresent(TEMPLATE_RESULT, Level.WARNING);
        handler.clearRecords();

        underTest.error(STRING_TEMPLATE, 1, 2);
        handler.assertMessagePresent(TEMPLATE_RESULT, Level.SEVERE);
        handler.clearRecords();
    }

    class LogHandler extends Handler {

        List<LogRecord> records = new ArrayList<>();

        Level lastLevel = Level.FINEST;

        @Override
        public void publish(LogRecord record) {
            records.add(record);
        }

        @Override
        public void close() {
        }

        @Override
        public void flush() {
        }

        void assertMessagePresent(String message, Level level) {
            assertFalse(records.isEmpty());
            assertEquals(1, records.stream().filter(r -> level.equals(r.getLevel()))
                    .filter(r -> message.equals(r.getMessage())).count());
        }

        void assertMessagePresent(String message, Level level, Throwable throwable) {
            assertFalse(records.isEmpty());
            assertEquals(1, records.stream().filter(r -> level.equals(r.getLevel()))
                    .filter(r -> message.equals(r.getMessage())).filter(r -> throwable.equals(r.getThrown())).count());
        }

        void clearRecords() {
            records.clear();
        }
    }
}
