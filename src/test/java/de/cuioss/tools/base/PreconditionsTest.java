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

import static de.cuioss.tools.base.Preconditions.checkArgument;
import static de.cuioss.tools.base.Preconditions.checkState;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@DisplayName("Preconditions should")
class PreconditionsTest {

    private static final String MESSAGE = "message";
    private static final String MESSAGE_TEMPLATE = "message %s";
    private static final String MESSAGE_PARAMETER = "parameter";
    private static final String MESSAGE_TEMPLATE_RESULT = "message parameter";

    @Nested
    @DisplayName("handle checkArgument")
    class CheckArgumentTest {

        @Test
        @DisplayName("pass for true condition")
        void shouldPassForTrueCondition() {
            checkArgument(true);
            checkArgument(true, MESSAGE);
            checkArgument(true, MESSAGE_TEMPLATE, MESSAGE_PARAMETER);
        }

        @Test
        @DisplayName("throw IllegalArgumentException for false condition without message")
        void shouldThrowForFalseCondition() {
            assertThrows(IllegalArgumentException.class, () -> checkArgument(false));
        }

        @Test
        @DisplayName("throw IllegalArgumentException with message for false condition")
        void shouldThrowWithMessageForFalseCondition() {
            var ex = assertThrows(IllegalArgumentException.class, () -> checkArgument(false, MESSAGE));
            assertEquals(MESSAGE, ex.getMessage());
        }

        @Test
        @DisplayName("throw IllegalArgumentException with formatted message for false condition")
        void shouldThrowWithFormattedMessageForFalseCondition() {
            var ex = assertThrows(IllegalArgumentException.class, 
                () -> checkArgument(false, MESSAGE_TEMPLATE, MESSAGE_PARAMETER));
            assertEquals(MESSAGE_TEMPLATE_RESULT, ex.getMessage());
        }
    }

    @Nested
    @DisplayName("handle checkState")
    class CheckStateTest {

        @Test
        @DisplayName("pass for true condition")
        void shouldPassForTrueCondition() {
            checkState(true);
            checkState(true, MESSAGE);
            checkState(true, MESSAGE_TEMPLATE, MESSAGE_PARAMETER);
        }

        @Test
        @DisplayName("throw IllegalStateException for false condition without message")
        void shouldThrowForFalseCondition() {
            assertThrows(IllegalStateException.class, () -> checkState(false));
        }

        @Test
        @DisplayName("throw IllegalStateException with message for false condition")
        void shouldThrowWithMessageForFalseCondition() {
            var ex = assertThrows(IllegalStateException.class, () -> checkState(false, MESSAGE));
            assertEquals(MESSAGE, ex.getMessage());
        }

        @Test
        @DisplayName("throw IllegalStateException with formatted message for false condition")
        void shouldThrowWithFormattedMessageForFalseCondition() {
            var ex = assertThrows(IllegalStateException.class, 
                () -> checkState(false, MESSAGE_TEMPLATE, MESSAGE_PARAMETER));
            assertEquals(MESSAGE_TEMPLATE_RESULT, ex.getMessage());
        }
    }
}
