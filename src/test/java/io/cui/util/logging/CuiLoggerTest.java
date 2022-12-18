package io.cui.util.logging;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.function.Supplier;
import java.util.logging.Level;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

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

        throwable = new RuntimeException();
    }

    @Test
    void shouldHandleLogGuard() {
        java.util.logging.Logger reference = java.util.logging.Logger.getLogger(CuiLogger.class.getName());

        assertEquals(underTest.isTraceEnabled(), reference.isLoggable(Level.FINER));
        assertEquals(underTest.isDebugEnabled(), reference.isLoggable(Level.FINE));
        assertEquals(underTest.isInfoEnabled(), reference.isLoggable(Level.INFO));
        assertEquals(underTest.isWarnEnabled(), reference.isLoggable(Level.WARNING));
        assertEquals(underTest.isErrorEnabled(), reference.isLoggable(Level.SEVERE));

    }

    @Test
    void shouldHandleNamedLogger() {
        assertFalse(CuiLoggerFactory.getLogger(this.getClass()).isDebugEnabled());
        assertEquals("io.cui.util.logging.CuiLoggerTest", CuiLoggerFactory.getLogger().getName());
    }

    @Test
    void shouldHandleTraceLogging() {

        underTest.trace(TRACE);
        handler.assertMessagePresent(TRACE, Level.FINER);
        handler.clearRecords();

        underTest.trace(TRACE, throwable);
        handler.assertMessagePresent(TRACE, Level.FINER, throwable);
    }

    @Test
    void shouldHandleTraceSupplierLogging() {

        underTest.trace(() -> TRACE);
        handler.assertMessagePresent(TRACE, Level.FINER);
        handler.clearRecords();

        underTest.trace(throwable, () -> TRACE);
        handler.assertMessagePresent(TRACE, Level.FINER, throwable);
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

    @Test
    void shouldHandleDebugLogging() {
        underTest.debug(DEBUG);
        handler.assertMessagePresent(DEBUG, Level.FINE);
        handler.clearRecords();

        underTest.debug(DEBUG, throwable);
        handler.assertMessagePresent(DEBUG, Level.FINE, throwable);
    }

    @Test
    void shouldHandleDebugSupplierLogging() {
        underTest.debug(() -> DEBUG);
        handler.assertMessagePresent(DEBUG, Level.FINE);
        handler.clearRecords();

        underTest.debug(throwable, () -> DEBUG);
        handler.assertMessagePresent(DEBUG, Level.FINE, throwable);
    }

    @Test
    void shouldHandleInfoLogging() {
        underTest.info(INFO);
        handler.assertMessagePresent(INFO, Level.INFO);
        handler.clearRecords();

        underTest.info(INFO, throwable);
        handler.assertMessagePresent(INFO, Level.INFO, throwable);
    }

    @Test
    void shouldHandleInfoSupplierLogging() {
        underTest.info(() -> INFO);
        handler.assertMessagePresent(INFO, Level.INFO);
        handler.clearRecords();

        underTest.info(throwable, () -> INFO);
        handler.assertMessagePresent(INFO, Level.INFO, throwable);
    }

    @Test
    void shouldHandleWarnLogging() {
        underTest.warn(WARN);
        handler.assertMessagePresent(WARN, Level.WARNING);
        handler.clearRecords();

        underTest.warn(WARN, throwable);
        handler.assertMessagePresent(WARN, Level.WARNING, throwable);
    }

    @Test
    void shouldHandleWarnSupplierLogging() {
        underTest.warn(() -> WARN);
        handler.assertMessagePresent(WARN, Level.WARNING);
        handler.clearRecords();

        underTest.warn(throwable, () -> WARN);
        handler.assertMessagePresent(WARN, Level.WARNING, throwable);
    }

    @Test
    void shouldHandleErrorLogging() {
        underTest.error(ERROR);
        handler.assertMessagePresent(ERROR, Level.SEVERE);
        handler.clearRecords();

        underTest.error(ERROR, throwable);
        handler.assertMessagePresent(ERROR, Level.SEVERE, throwable);
    }

    @Test
    void shouldHandleErrorSupplierLogging() {
        underTest.error(() -> ERROR);
        handler.assertMessagePresent(ERROR, Level.SEVERE);
        handler.clearRecords();

        underTest.error(throwable, () -> ERROR);
        handler.assertMessagePresent(ERROR, Level.SEVERE, throwable);
    }

    @Test
    void shouldHandleFormatting() {
        underTest.trace(SLF4J_TEMPLATE, 1, 2);
        handler.assertMessagePresent(TEMPLATE_RESULT, Level.FINER);
        handler.clearRecords();

        underTest.trace(throwable, SLF4J_TEMPLATE, 1, 2);
        handler.assertMessagePresent(TEMPLATE_RESULT, Level.FINER, throwable);
        handler.clearRecords();

        underTest.trace(STRING_TEMPLATE, 1, 2);
        handler.assertMessagePresent(TEMPLATE_RESULT, Level.FINER);
        handler.clearRecords();

        underTest.debug(STRING_TEMPLATE, 1, 2);
        handler.assertMessagePresent(TEMPLATE_RESULT, Level.FINE);
        handler.clearRecords();

        underTest.debug(throwable, STRING_TEMPLATE, 1, 2);
        handler.assertMessagePresent(TEMPLATE_RESULT, Level.FINE, throwable);
        handler.clearRecords();

        underTest.info(STRING_TEMPLATE, 1, 2);
        handler.assertMessagePresent(TEMPLATE_RESULT, Level.INFO);
        handler.clearRecords();

        underTest.info(throwable, STRING_TEMPLATE, 1, 2);
        handler.assertMessagePresent(TEMPLATE_RESULT, Level.INFO, throwable);
        handler.clearRecords();

        underTest.warn(STRING_TEMPLATE, 1, 2);
        handler.assertMessagePresent(TEMPLATE_RESULT, Level.WARNING);
        handler.clearRecords();

        underTest.warn(throwable, STRING_TEMPLATE, 1, 2);
        handler.assertMessagePresent(TEMPLATE_RESULT, Level.WARNING, throwable);
        handler.clearRecords();

        underTest.error(STRING_TEMPLATE, 1, 2);
        handler.assertMessagePresent(TEMPLATE_RESULT, Level.SEVERE);
        handler.clearRecords();

        underTest.error(throwable, STRING_TEMPLATE, 1, 2);
        handler.assertMessagePresent(TEMPLATE_RESULT, Level.SEVERE, throwable);
    }

}
