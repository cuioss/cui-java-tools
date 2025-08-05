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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for {@link CuiLoggerFactory} ensuring proper initialization
 * without circular dependencies.
 */
class CuiLoggerFactoryTest {

    @Test
    void shouldCreateLoggerFromClass() {
        CuiLogger logger = CuiLoggerFactory.getLogger(CuiLoggerFactoryTest.class);
        assertNotNull(logger);
        assertEquals(CuiLoggerFactoryTest.class.getName(), logger.getName());
    }

    @Test
    void shouldCreateLoggerFromClassName() {
        String className = "com.example.TestClass";
        CuiLogger logger = CuiLoggerFactory.getLogger(className);
        assertNotNull(logger);
        assertEquals(className, logger.getName());
    }

    @Test
    void shouldAutoDetectCallerClass() {
        CuiLogger logger = CuiLoggerFactory.getLogger();
        assertNotNull(logger);
        assertEquals(CuiLoggerFactoryTest.class.getName(), logger.getName());
    }

    @Test
    void shouldHandleNestedCallerDetection() {
        CuiLogger logger = createLoggerIndirectly();
        assertNotNull(logger);
        assertEquals(CuiLoggerFactoryTest.class.getName(), logger.getName());
    }

    private CuiLogger createLoggerIndirectly() {
        return CuiLoggerFactory.getLogger();
    }

    @Test
    void shouldNotCauseCircularDependencyDuringInitialization() {
        // This test verifies that CuiLoggerFactory can be used without
        // causing circular dependency issues with MoreReflection
        CuiLogger logger1 = CuiLoggerFactory.getLogger(CuiLoggerFactoryTest.class);
        assertNotNull(logger1);

        // Create another logger to ensure consistent behavior
        CuiLogger logger2 = CuiLoggerFactory.getLogger();
        assertNotNull(logger2);

        // Both should work without initialization issues
        assertDoesNotThrow(() -> logger1.debug("Test message"));
        assertDoesNotThrow(() -> logger2.debug("Test message"));
    }

    @Test
    void shouldCreateLoggerWithoutReflectionDependency() {
        // This test ensures that CuiLoggerFactory doesn't depend on MoreReflection
        // for its core functionality
        CuiLogger logger = new TestLoggerCreator().createLogger();
        assertNotNull(logger);
        assertEquals(TestLoggerCreator.class.getName(), logger.getName());
    }

    /**
     * Helper class to test logger creation from a different context
     */
    private static class TestLoggerCreator {
        CuiLogger createLogger() {
            return CuiLoggerFactory.getLogger();
        }
    }

    @Test
    void shouldHandleMultithreadedInitialization() throws InterruptedException {
        // Test concurrent initialization to ensure thread safety
        final int threadCount = 10;
        Thread[] threads = new Thread[threadCount];
        CuiLogger[] loggers = new CuiLogger[threadCount];

        for (int i = 0; i < threadCount; i++) {
            final int index = i;
            threads[i] = new Thread(() -> {
                loggers[index] = CuiLoggerFactory.getLogger(CuiLoggerFactoryTest.class);
            });
            threads[i].start();
        }

        for (Thread thread : threads) {
            thread.join();
        }

        // All loggers should be created successfully
        for (CuiLogger logger : loggers) {
            assertNotNull(logger);
            assertEquals(CuiLoggerFactoryTest.class.getName(), logger.getName());
        }
    }
}