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

    @Nested
    @DisplayName("handle isAnyTrue")
    class IsAnyTrueTest {
        
        @ParameterizedTest(name = "return {1} for values {0}")
        @CsvSource({
            "'true', true",
            "'true,true', true",
            "'true,false', true",
            "'false,false', false"
        })
        void shouldHandleValidCases(String input, boolean expected) {
            var values = input.split(",");
            var booleans = new boolean[values.length];
            for (int i = 0; i < values.length; i++) {
                booleans[i] = Boolean.parseBoolean(values[i]);
            }
            assertEquals(expected, isAnyTrue(booleans));
        }

        @Test
        @DisplayName("handle edge cases")
        void shouldHandleEdgeCases() {
            assertFalse(isAnyTrue());
            assertFalse(isAnyTrue((boolean[]) null));
        }
    }

    @Nested
    @DisplayName("handle isAnyFalse")
    class IsAnyFalseTest {
        
        @ParameterizedTest(name = "return {1} for values {0}")
        @CsvSource({
            "'true', false",
            "'true,false', true",
            "'false,false', true",
            "'true,true', false"
        })
        void shouldHandleValidCases(String input, boolean expected) {
            var values = input.split(",");
            var booleans = new boolean[values.length];
            for (int i = 0; i < values.length; i++) {
                booleans[i] = Boolean.parseBoolean(values[i]);
            }
            assertEquals(expected, isAnyFalse(booleans));
        }

        @Test
        @DisplayName("handle edge cases")
        void shouldHandleEdgeCases() {
            assertFalse(isAnyFalse());
            assertFalse(isAnyFalse((boolean[]) null));
        }
    }

    @Nested
    @DisplayName("handle areAllFalse")
    class AreAllFalseTest {
        
        @ParameterizedTest(name = "return {1} for values {0}")
        @CsvSource({
            "'true', false",
            "'true,false', false",
            "'false,false', true",
            "'true,true', false"
        })
        void shouldHandleValidCases(String input, boolean expected) {
            var values = input.split(",");
            var booleans = new boolean[values.length];
            for (int i = 0; i < values.length; i++) {
                booleans[i] = Boolean.parseBoolean(values[i]);
            }
            assertEquals(expected, areAllFalse(booleans));
        }

        @Test
        @DisplayName("handle edge cases")
        void shouldHandleEdgeCases() {
            assertFalse(areAllFalse());
            assertFalse(areAllFalse((boolean[]) null));
        }
    }

    @Nested
    @DisplayName("handle areAllTrue")
    class AreAllTrueTest {
        
        @ParameterizedTest(name = "return {1} for values {0}")
        @CsvSource({
            "'true', true",
            "'true,false', false",
            "'false,false', false",
            "'true,true', true"
        })
        void shouldHandleValidCases(String input, boolean expected) {
            var values = input.split(",");
            var booleans = new boolean[values.length];
            for (int i = 0; i < values.length; i++) {
                booleans[i] = Boolean.parseBoolean(values[i]);
            }
            assertEquals(expected, areAllTrue(booleans));
        }

        @Test
        @DisplayName("handle edge cases")
        void shouldHandleEdgeCases() {
            assertTrue(areAllTrue());
            assertTrue(areAllTrue((boolean[]) null));
        }
    }

    @Nested
    @DisplayName("handle isValidBoolean")
    class IsValidBooleanTest {
        
        @ParameterizedTest(name = "return true for valid boolean string '{0}'")
        @ValueSource(strings = {"true", "false", "TrUe", "FaLsE"})
        void shouldHandleValidCases(String input) {
            assertTrue(BooleanOperations.isValidBoolean(input));
        }

        @ParameterizedTest(name = "return false for invalid boolean string '{0}'")
        @ValueSource(strings = {"", " ", " true ", "true ", "yes", "no"})
        void shouldHandleInvalidCases(String input) {
            assertFalse(BooleanOperations.isValidBoolean(input));
        }

        @Test
        @DisplayName("handle null input")
        void shouldHandleNullCase() {
            assertFalse(assertDoesNotThrow(() -> BooleanOperations.isValidBoolean(null)));
        }
    }
}
