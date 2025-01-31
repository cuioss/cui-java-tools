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
package de.cuioss.tools.base;

import static de.cuioss.tools.base.BooleanOperations.areAllFalse;
import static de.cuioss.tools.base.BooleanOperations.areAllTrue;
import static de.cuioss.tools.base.BooleanOperations.isAnyFalse;
import static de.cuioss.tools.base.BooleanOperations.isAnyTrue;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

@DisplayName("BooleanOperations should")
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
            assertFalse(isAnyTrue(new boolean[0]), "Empty array should return false");
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
            assertFalse(isAnyFalse(new boolean[0]), "Empty array should return false");
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
            assertFalse(areAllFalse(new boolean[0]), "Empty array should return false");
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
            assertTrue(areAllTrue(new boolean[0]), "Empty array should return true");
        }
    }

    @Nested
    @DisplayName("handle isValidBoolean")
    class IsValidBooleanTest {
        
        @ParameterizedTest(name = "return true for valid boolean string '{0}'")
        @ValueSource(strings = {
            "true", "false",
            "TrUe", "FaLsE",
            "TRUE", "FALSE"
        })
        void shouldHandleValidCases(String input) {
            assertTrue(BooleanOperations.isValidBoolean(input),
                () -> "Should accept '" + input + "' as valid boolean string");
        }

        @ParameterizedTest(name = "return false for invalid boolean string '{0}'")
        @ValueSource(strings = {
            "", " ", "\t", "\n",
            " true ", "true ",
            "yes", "no",
            "0", "1",
            "on", "off"
        })
        void shouldHandleInvalidCases(String input) {
            assertFalse(BooleanOperations.isValidBoolean(input),
                () -> "Should reject '" + input + "' as invalid boolean string");
        }

        @Test
        @DisplayName("handle null input")
        void shouldHandleNullCase() {
            assertFalse(assertDoesNotThrow(() -> BooleanOperations.isValidBoolean(null),
                "Should not throw exception for null input"));
        }
    }

    @Nested
    @DisplayName("handle performance")
    class PerformanceTest {
        
        @Test
        @DisplayName("handle large arrays efficiently")
        void shouldHandleLargeArrays() {
            // Create large array with alternating values
            var size = 10000;
            var largeArray = new boolean[size];
            for (int i = 0; i < size; i++) {
                largeArray[i] = i % 2 == 0;
            }
            
            // Test isAnyTrue performance
            assertDoesNotThrow(() -> {
                var result = isAnyTrue(largeArray);
                assertTrue(result, "Should find true in alternating array");
            });
            
            // Test isAnyFalse performance
            assertDoesNotThrow(() -> {
                var result = isAnyFalse(largeArray);
                assertTrue(result, "Should find false in alternating array");
            });
            
            // Test areAllTrue performance
            assertDoesNotThrow(() -> {
                var result = areAllTrue(largeArray);
                assertFalse(result, "Should not be all true in alternating array");
            });
            
            // Test areAllFalse performance
            assertDoesNotThrow(() -> {
                var result = areAllFalse(largeArray);
                assertFalse(result, "Should not be all false in alternating array");
            });
        }
        
        @Test
        @DisplayName("handle worst-case scenarios efficiently")
        void shouldHandleWorstCaseScenarios() {
            var size = 10000;
            
            // Test finding single true at end
            var singleTrueAtEnd = new boolean[size];
            singleTrueAtEnd[size - 1] = true;
            
            assertDoesNotThrow(() -> {
                var result = isAnyTrue(singleTrueAtEnd);
                assertTrue(result, "Should find single true at end");
            });
            
            // Test finding single false at end
            var singleFalseAtEnd = new boolean[size];
            for (int i = 0; i < size; i++) {
                singleFalseAtEnd[i] = true;
            }
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
            var size = 1000;
            var sharedArray = new boolean[size];
            for (int i = 0; i < size; i++) {
                sharedArray[i] = i % 2 == 0;
            }
            
            var threadCount = 10;
            var executor = Executors.newFixedThreadPool(threadCount);
            var futures = new ArrayList<Future<?>>();
            
            try {
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
            } finally {
                executor.shutdownNow();
            }
        }
    }
}
