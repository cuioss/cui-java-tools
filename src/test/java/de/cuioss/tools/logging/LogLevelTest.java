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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Test class for {@link LogLevel} ensuring proper level mapping and behavior
 * according to logging guidelines.
 */
class LogLevelTest {

    private static final String TEST_MESSAGE = "test message";
    private static final RuntimeException TEST_EXCEPTION = new RuntimeException("test exception");
    private final Logger logger = Logger.getLogger(LogLevelTest.class.getName());

    @Test
    void shouldMapJulLevelsCorrectly() {
        // Test ALL level
        assertEquals(LogLevel.TRACE, LogLevel.from(Level.ALL));

        // Test FINEST/FINER/FINE levels
        assertEquals(LogLevel.TRACE, LogLevel.from(Level.FINEST));
        assertEquals(LogLevel.TRACE, LogLevel.from(Level.FINER));
        assertEquals(LogLevel.DEBUG, LogLevel.from(Level.FINE));

        // Test CONFIG/INFO levels
        assertEquals(LogLevel.DEBUG, LogLevel.from(Level.CONFIG));
        assertEquals(LogLevel.INFO, LogLevel.from(Level.INFO));

        // Test WARNING/SEVERE levels
        assertEquals(LogLevel.WARN, LogLevel.from(Level.WARNING));
        assertEquals(LogLevel.ERROR, LogLevel.from(Level.SEVERE));

        // Test OFF level
        assertEquals(LogLevel.OFF, LogLevel.from(Level.OFF));
    }

    @Test
    void shouldHandleLogLevelEnabled() {
        // Given
        logger.setLevel(Level.ALL);

        // Then
        assertTrue(LogLevel.TRACE.isEnabled(logger));
        assertTrue(LogLevel.DEBUG.isEnabled(logger));
        assertTrue(LogLevel.INFO.isEnabled(logger));
        assertTrue(LogLevel.WARN.isEnabled(logger));
        assertTrue(LogLevel.ERROR.isEnabled(logger));

        // When
        logger.setLevel(Level.OFF);

        // Then
        assertFalse(LogLevel.TRACE.isEnabled(logger));
        assertFalse(LogLevel.DEBUG.isEnabled(logger));
        assertFalse(LogLevel.INFO.isEnabled(logger));
        assertFalse(LogLevel.WARN.isEnabled(logger));
        assertFalse(LogLevel.ERROR.isEnabled(logger));
    }

    @Test
    void shouldHandleLogLevelHierarchy() {
        // Given
        logger.setLevel(Level.INFO);

        // Then
        assertFalse(LogLevel.TRACE.isEnabled(logger));
        assertFalse(LogLevel.DEBUG.isEnabled(logger));
        assertTrue(LogLevel.INFO.isEnabled(logger));
        assertTrue(LogLevel.WARN.isEnabled(logger));
        assertTrue(LogLevel.ERROR.isEnabled(logger));
    }

    @Test
    void shouldHandleActualLogging() {
        // Given
        logger.setLevel(Level.ALL);

        // When/Then - no assertions needed as per logging rules
        LogLevel.TRACE.handleActualLog(logger, TEST_MESSAGE, null);
        LogLevel.DEBUG.handleActualLog(logger, TEST_MESSAGE, TEST_EXCEPTION);
        LogLevel.INFO.handleActualLog(logger, TEST_MESSAGE, null);
        LogLevel.WARN.handleActualLog(logger, TEST_MESSAGE, TEST_EXCEPTION);
        LogLevel.ERROR.handleActualLog(logger, TEST_MESSAGE, null);
    }

    @Test
    void shouldHandleSupplierLogging() {
        // Given
        logger.setLevel(Level.ALL);
        Supplier<String> messageSupplier = () -> TEST_MESSAGE;

        // When/Then - no assertions needed as per logging rules
        LogLevel.TRACE.log(logger, messageSupplier, null);
        LogLevel.DEBUG.log(logger, messageSupplier, TEST_EXCEPTION);
        LogLevel.INFO.log(logger, messageSupplier, null);
        LogLevel.WARN.log(logger, messageSupplier, TEST_EXCEPTION);
        LogLevel.ERROR.log(logger, messageSupplier, null);
    }

    @Test
    void shouldHandleParameterizedLogging() {
        // Given
        logger.setLevel(Level.ALL);
        String template = "Message with parameter: {}";
        String parameter = "test";

        // When/Then - no assertions needed as per logging rules
        LogLevel.TRACE.log(logger, template, parameter);
        LogLevel.DEBUG.log(logger, TEST_EXCEPTION, template, parameter);
        LogLevel.INFO.log(logger, template, parameter);
        LogLevel.WARN.log(logger, TEST_EXCEPTION, template, parameter);
        LogLevel.ERROR.log(logger, template, parameter);
    }

    @Test
    void shouldHandleNullValues() {
        // Given
        logger.setLevel(Level.ALL);

        // When/Then - no assertions needed as per logging rules
        LogLevel.INFO.handleActualLog(logger, null, null);
        LogLevel.ERROR.handleActualLog(logger, null, TEST_EXCEPTION);
        LogLevel.WARN.log(logger, null, (Object[]) null);
    }
}
