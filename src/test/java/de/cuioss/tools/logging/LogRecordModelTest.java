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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/**
 * Test class for {@link LogRecordModel} ensuring proper log message formatting
 * and integration with {@link CuiLogger}.
 */
class LogRecordModelTest {

    private static final String PREFIX = "CUI-100";
    private static final CuiLogger log = new CuiLogger(LogRecordModelTest.class);

    private final LogRecord infoModel = LogRecordModel.builder()
            .identifier(100)
            .prefix("CUI")
            .template("{}-%s")
            .build();

    private final LogRecord errorModel = LogRecordModel.builder()
            .identifier(500)
            .prefix("ERROR")
            .template("Operation failed: {}")
            .build();

    private final LogRecord warnModel = LogRecordModel.builder()
            .identifier(300)
            .prefix("WARN")
            .template("Warning condition: {}")
            .build();

    @Test
    void shouldHandlePrefix() {
        assertEquals(PREFIX, infoModel.resolveIdentifierString());
        assertEquals(PREFIX + ": A-2", infoModel.format("A", 2));
    }

    @Test
    void shouldHandleInfoLevel() {
        var result = "Operation completed";
        assertDoesNotThrow(() -> log.info(infoModel.format(result, "success")));
    }

    @Test
    void shouldHandleErrorLevel() {
        var errorMessage = "Database connection failed";
        try {
            throw new RuntimeException(errorMessage);
        } catch (Exception e) {
            log.error(errorModel.format(errorMessage));
            assertDoesNotThrow(() -> log.error(e, errorModel.format(errorMessage)));
        }
    }

    @Test
    void shouldHandleWarnLevel() {
        var warningCondition = "Resource usage above 80%";
        assertDoesNotThrow(() -> log.warn(warnModel.format(warningCondition)));
    }

    @Test
    void shouldHandleMultipleParameters() {
        var complexModel = LogRecordModel.builder()
                .identifier(200)
                .prefix("COMPLEX")
                .template("Value1: {}, Value2: {}, Value3: %s")
                .build();

        var result = complexModel.format("first", "second", "third");
        assertEquals("COMPLEX-200: Value1: first, Value2: second, Value3: third", result);
        log.info(result);
    }

    @Test
    void shouldHandleNullParameters() {
        var result = infoModel.format(null, null);
        assertEquals(PREFIX + ": null-null", result);
        log.info(result);
    }

    @Test
    void shouldHandleExceptionFormatting() {
        var exceptionModel = LogRecordModel.builder()
                .identifier(600)
                .prefix("EX")
                .template("Exception occurred: {} - Details: %s")
                .build();

        try {
            throw new IllegalArgumentException("Invalid input");
        } catch (Exception e) {
            var result = exceptionModel.format(e.getClass().getSimpleName(), e.getMessage());
            assertEquals("EX-600: Exception occurred: IllegalArgumentException - Details: Invalid input", result);
            log.error(e, result);
        }
    }
}
