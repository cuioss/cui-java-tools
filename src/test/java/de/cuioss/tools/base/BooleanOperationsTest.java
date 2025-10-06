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
    @DisplayName("handle random arrays with correctness verification")
    class RandomArrayTest {

        // Helper methods to calculate expected results
        private boolean calculateIsAnyTrue(boolean[] array) {
            if (array == null || array.length == 0) {
                return false;
            }
            for (boolean value : array) {
                if (value) return true;
            }
            return false;
        }

        private boolean calculateIsAnyFalse(boolean[] array) {
            if (array == null || array.length == 0) {
                return false;
            }
            for (boolean value : array) {
                if (!value) return true;
            }
            return false;
        }

        private boolean calculateAreAllTrue(boolean[] array) {
            if (array == null || array.length == 0) {
                return true; // Empty arrays return true for areAllTrue
            }
            for (boolean value : array) {
                if (!value) return false;
            }
            return true;
        }

        private boolean calculateAreAllFalse(boolean[] array) {
            if (array == null || array.length == 0) {
                return false; // Empty arrays return false for areAllFalse
            }
            for (boolean value : array) {
                if (value) return false;
            }
            return true;
        }

        @Test
        @DisplayName("verify correctness with typical varargs sizes (1-5 elements)")
        void shouldHandleTypicalVarargsArrays() {
            // Test multiple times with different random arrays
            for (int iteration = 0; iteration < 20; iteration++) {
                // Generate realistic size (1-5 elements, typical for varargs)
                var size = Generators.integers(1, 6).next();
                var testArray = new boolean[size];

                // Fill with random values
                for (int i = 0; i < size; i++) {
                    testArray[i] = Generators.booleans().next();
                }

                // Verify isAnyTrue
                var expectedAnyTrue = calculateIsAnyTrue(testArray);
                var actualAnyTrue = isAnyTrue(testArray);
                assertEquals(expectedAnyTrue, actualAnyTrue,
                        "isAnyTrue failed for array: " + Arrays.toString(testArray));

                // Verify isAnyFalse
                var expectedAnyFalse = calculateIsAnyFalse(testArray);
                var actualAnyFalse = isAnyFalse(testArray);
                assertEquals(expectedAnyFalse, actualAnyFalse,
                        "isAnyFalse failed for array: " + Arrays.toString(testArray));

                // Verify areAllTrue
                var expectedAllTrue = calculateAreAllTrue(testArray);
                var actualAllTrue = areAllTrue(testArray);
                assertEquals(expectedAllTrue, actualAllTrue,
                        "areAllTrue failed for array: " + Arrays.toString(testArray));

                // Verify areAllFalse
                var expectedAllFalse = calculateAreAllFalse(testArray);
                var actualAllFalse = areAllFalse(testArray);
                assertEquals(expectedAllFalse, actualAllFalse,
                        "areAllFalse failed for array: " + Arrays.toString(testArray));
            }
        }

        @Test
        @DisplayName("handle edge cases correctly")
        void shouldHandleEdgeCases() {
            // Test with typical varargs size but worst-case element positioning
            var size = 5; // Typical varargs size
            
            // Test finding single true at end (worst case for isAnyTrue)
            var singleTrueAtEnd = new boolean[size];
            singleTrueAtEnd[size - 1] = true;

            assertTrue(isAnyTrue(singleTrueAtEnd), "Should find single true at end");
            assertTrue(isAnyFalse(singleTrueAtEnd), "Should find falses before the true");
            assertFalse(areAllTrue(singleTrueAtEnd), "Not all values are true");
            assertFalse(areAllFalse(singleTrueAtEnd), "Not all values are false");

            // Test finding single false at end (worst case for isAnyFalse)
            var singleFalseAtEnd = new boolean[size];
            Arrays.fill(singleFalseAtEnd, true);
            singleFalseAtEnd[size - 1] = false;

            assertTrue(isAnyTrue(singleFalseAtEnd), "Should find trues before the false");
            assertTrue(isAnyFalse(singleFalseAtEnd), "Should find single false at end");
            assertFalse(areAllTrue(singleFalseAtEnd), "Not all values are true");
            assertFalse(areAllFalse(singleFalseAtEnd), "Not all values are false");

            // Test with all true
            var allTrue = new boolean[size];
            Arrays.fill(allTrue, true);

            assertTrue(isAnyTrue(allTrue), "Should find true values");
            assertFalse(isAnyFalse(allTrue), "Should not find any false");
            assertTrue(areAllTrue(allTrue), "All values are true");
            assertFalse(areAllFalse(allTrue), "Not all values are false");

            // Test with all false
            var allFalse = new boolean[size];
            // Arrays are false by default
            
            assertFalse(isAnyTrue(allFalse), "Should not find any true");
            assertTrue(isAnyFalse(allFalse), "Should find false values");
            assertFalse(areAllTrue(allFalse), "Not all values are true");
            assertTrue(areAllFalse(allFalse), "All values are false");
        }
    }

    @Nested
    @DisplayName("handle concurrent access")
    class ConcurrentTest {

        @Test
        @DisplayName("handle concurrent reads safely")
        void shouldHandleConcurrentReads() {
            // Use realistic varargs size
            var size = Generators.integers(3, 6).next();
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
