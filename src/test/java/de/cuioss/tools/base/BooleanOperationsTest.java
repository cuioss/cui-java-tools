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
}
