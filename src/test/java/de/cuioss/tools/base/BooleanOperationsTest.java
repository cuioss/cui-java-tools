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
package de.cuioss.tools.base;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static de.cuioss.tools.base.BooleanOperations.*;
import static org.junit.jupiter.api.Assertions.*;

@DisplayName("BooleanOperations should")
@EnableGeneratorController
class BooleanOperationsTest {

    private boolean[] toBooleanArray(String input) {
        if (input == null || input.isEmpty()) {
            return new boolean[0];
        }
        var values = input.split(",");
        var booleans = new boolean[values.length];
        for (int i = 0; i < values.length; i++) {
            booleans[i] = Boolean.parseBoolean(values[i]);
        }
        return booleans;
    }

    @Nested
    @DisplayName("handle isAnyTrue")
    class IsAnyTrueTest {

        @ParameterizedTest(name = "return {1} when checking array [{0}] for any true value")
        @CsvSource({
                "'true', true",
                "'true,true', true",
                "'true,false', true",
                "'false,true,false', true",
                "'false,false', false",
                "'', false"
        })
        void shouldHandleValidCases(String input, boolean expected) {
            assertEquals(expected, isAnyTrue(toBooleanArray(input)));
        }

        @Test
        @DisplayName("handle edge cases")
        void shouldHandleEdgeCases() {
            assertFalse(isAnyTrue(), "Empty varargs should return false");
            assertFalse(isAnyTrue((boolean[]) null), "Null array should return false");
            assertFalse(isAnyTrue(), "Empty array should return false");
        }
    }

    @Nested
    @DisplayName("handle isAnyFalse")
    class IsAnyFalseTest {

        @ParameterizedTest(name = "return {1} when checking array [{0}] for any false value")
        @CsvSource({
                "'true', false",
                "'true,false', true",
                "'false,false', true",
                "'true,false,true', true",
                "'true,true', false",
                "'', false"
        })
        void shouldHandleValidCases(String input, boolean expected) {
            assertEquals(expected, isAnyFalse(toBooleanArray(input)));
        }

        @Test
        @DisplayName("handle edge cases")
        void shouldHandleEdgeCases() {
            assertFalse(isAnyFalse(), "Empty varargs should return false");
            assertFalse(isAnyFalse((boolean[]) null), "Null array should return false");
            assertFalse(isAnyFalse(), "Empty array should return false");
        }
    }

    @Nested
    @DisplayName("handle areAllFalse")
    class AreAllFalseTest {

        @ParameterizedTest(name = "return {1} when checking if all values are false in array [{0}]")
        @CsvSource({
                "'true', false",
                "'true,false', false",
                "'false,false', true",
                "'false,false,false', true",
                "'true,true', false",
                "'', false"
        })
        void shouldHandleValidCases(String input, boolean expected) {
            assertEquals(expected, areAllFalse(toBooleanArray(input)));
        }

        @Test
        @DisplayName("handle edge cases")
        void shouldHandleEdgeCases() {
            assertFalse(areAllFalse(), "Empty varargs should return false");
            assertFalse(areAllFalse((boolean[]) null), "Null array should return false");
            assertFalse(areAllFalse(), "Empty array should return false");
        }
    }

    @Nested
    @DisplayName("handle areAllTrue")
    class AreAllTrueTest {

        @ParameterizedTest(name = "return {1} when checking if all values are true in array [{0}]")
        @CsvSource({
                "'true', true",
                "'true,false', false",
                "'false,false', false",
                "'true,true,true', true",
                "'true,true', true",
                "'', true"
        })
        void shouldHandleValidCases(String input, boolean expected) {
            assertEquals(expected, areAllTrue(toBooleanArray(input)));
        }

        @Test
        @DisplayName("handle edge cases")
        void shouldHandleEdgeCases() {
            assertTrue(areAllTrue(), "Empty varargs should return true");
            assertTrue(areAllTrue((boolean[]) null), "Null array should return true");
            assertTrue(areAllTrue(), "Empty array should return true");
        }
    }

    @Nested
    @DisplayName("isValidBoolean should")
    class IsValidBooleanTest {

        @ParameterizedTest(name = "recognize valid boolean value: {0}")
        @ValueSource(strings = {"true", "TRUE", "True", "false", "FALSE", "False"})
        void shouldRecognizeValidBooleans(String input) {
            assertTrue(isValidBoolean(input));
        }

        @ParameterizedTest(name = "reject invalid boolean value: {0}")
        @ValueSource(strings = {"yes", "no", "1", "0", "on", "off", " true", "true ", "t", "f"})
        void shouldRejectInvalidBooleans(String input) {
            assertFalse(isValidBoolean(input));
        }

        @Test
        @DisplayName("handle edge cases correctly")
        void shouldHandleEdgeCases() {
            assertFalse(isValidBoolean(null), "null should be invalid");
            assertFalse(isValidBoolean(""), "empty string should be invalid");
            assertFalse(isValidBoolean(" "), "whitespace should be invalid");
        }

        @Test
        @DisplayName("be performant with many calls")
        void shouldBePerformant() {
            var start = System.nanoTime();
            for (int i = 0; i < 100_000; i++) {
                isValidBoolean("true");
                isValidBoolean("false");
                isValidBoolean("invalid");
            }
            var duration = System.nanoTime() - start;
            assertTrue(duration < TimeUnit.SECONDS.toNanos(1),
                    "Operation should complete within 1 second, took " +
                            TimeUnit.NANOSECONDS.toMillis(duration) + "ms");
        }
    }

    @Nested
    @DisplayName("handle performance")
    class PerformanceTest {

        @Test
        @DisplayName("handle large arrays efficiently")
        void shouldHandleLargeArrays() {
            // Create large array with random values
            var size = Generators.integers(5000, 15000).next();
            var largeArray = new boolean[size];
            for (int i = 0; i < size; i++) {
                largeArray[i] = Generators.booleans().next();
            }

            // Test isAnyTrue performance
            assertDoesNotThrow(() -> isAnyTrue(largeArray));

            // Test isAnyFalse performance
            assertDoesNotThrow(() -> isAnyFalse(largeArray));

            // Test areAllTrue performance
            assertDoesNotThrow(() -> areAllTrue(largeArray));

            // Test areAllFalse performance
            assertDoesNotThrow(() -> areAllFalse(largeArray));
        }

        @Test
        @DisplayName("handle worst-case scenarios efficiently")
        void shouldHandleWorstCaseScenarios() {
            var size = Generators.integers(5000, 15000).next();

            // Test finding single true at end
            var singleTrueAtEnd = new boolean[size];
            singleTrueAtEnd[size - 1] = true;

            assertDoesNotThrow(() -> {
                var result = isAnyTrue(singleTrueAtEnd);
                assertTrue(result, "Should find single true at end");
            });

            // Test finding single false at end
            var singleFalseAtEnd = new boolean[size];
            Arrays.fill(singleFalseAtEnd, true);
            singleFalseAtEnd[size - 1] = false;

            assertDoesNotThrow(() -> {
                var result = isAnyFalse(singleFalseAtEnd);
                assertTrue(result, "Should find single false at end");
            });
        }
    }

    @Nested
    @DisplayName("handle concurrent access")
    class ConcurrentTest {

        @Test
        @DisplayName("handle concurrent reads safely")
        void shouldHandleConcurrentReads() {
            var size = Generators.integers(500, 1500).next();
            var sharedArray = new boolean[size];
            for (int i = 0; i < size; i++) {
                sharedArray[i] = Generators.booleans().next();
            }

            var threadCount = 10;
            var futures = new ArrayList<Future<?>>();

            try (var executor = Executors.newFixedThreadPool(threadCount)) {
                // Submit multiple concurrent read tasks
                for (int i = 0; i < threadCount; i++) {
                    futures.add(executor.submit(() -> {
                        assertDoesNotThrow(() -> {
                            isAnyTrue(sharedArray);
                            isAnyFalse(sharedArray);
                            areAllTrue(sharedArray);
                            areAllFalse(sharedArray);
                        });
                        return null;
                    }));
                }

                // Wait for all tasks to complete
                for (var future : futures) {
                    assertDoesNotThrow(() -> future.get(5, TimeUnit.SECONDS));
                }
            }
        }
    }
}
