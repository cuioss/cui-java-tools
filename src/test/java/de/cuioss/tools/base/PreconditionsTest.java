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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.ArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static de.cuioss.tools.base.Preconditions.checkArgument;
import static de.cuioss.tools.base.Preconditions.checkState;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

        @ParameterizedTest
        @ValueSource(strings = {"", "custom message", "error: %s"})
        @DisplayName("throw IllegalArgumentException with various messages")
        void shouldThrowWithVariousMessages(String message) {
            var ex = assertThrows(IllegalArgumentException.class,
                    () -> checkArgument(false, message));
            assertEquals(message, ex.getMessage());
        }

        @Test
        @DisplayName("throw IllegalArgumentException for false condition without message")
        void shouldThrowForFalseCondition() {
            var ex = assertThrows(IllegalArgumentException.class, () -> checkArgument(false));
            assertInstanceOf(IllegalArgumentException.class, ex);
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

        @Test
        @DisplayName("throw IllegalArgumentException with null message parameter")
        void shouldHandleNullMessageParameter() {
            var ex = assertThrows(IllegalArgumentException.class,
                    () -> checkArgument(false, MESSAGE_TEMPLATE, (Object) null));
            assertEquals("message null", ex.getMessage());
        }

        @Test
        void shouldHandleNullPointerOnAssertArgumentFalse() {
            assertThrows(NullPointerException.class, () -> {
                Boolean value = null;
                checkArgument(value);
            });
        }

        @Test
        void shouldHandleNullPointerOnAssertArgumentTrue() {
            assertThrows(NullPointerException.class, () -> {
                Boolean value = null;
                checkArgument(value);
            });
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

        @ParameterizedTest
        @ValueSource(strings = {"", "custom message", "error: %s"})
        @DisplayName("throw IllegalStateException with various messages")
        void shouldThrowWithVariousMessages(String message) {
            var ex = assertThrows(IllegalStateException.class,
                    () -> checkState(false, message));
            assertEquals(message, ex.getMessage());
        }

        @Test
        @DisplayName("throw IllegalStateException for false condition without message")
        void shouldThrowForFalseCondition() {
            var ex = assertThrows(IllegalStateException.class, () -> checkState(false));
            assertInstanceOf(IllegalStateException.class, ex);
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

        @Test
        @DisplayName("throw IllegalStateException with null message parameter")
        void shouldHandleNullMessageParameter() {
            var ex = assertThrows(IllegalStateException.class,
                    () -> checkState(false, MESSAGE_TEMPLATE, (Object) null));
            assertEquals("message null", ex.getMessage());
        }
    }

    @Nested
    @DisplayName("handle complex message formatting")
    class ComplexMessageFormattingTest {

        @Test
        @DisplayName("format complex object arrays")
        void shouldFormatComplexObjects() {
            var complexObj = new Object() {
                @Override
                public String toString() {
                    return "CustomObject{with special chars: %s, {}, []}";
                }
            };

            var ex = assertThrows(IllegalArgumentException.class,
                    () -> checkArgument(false, "Complex format: %s, %s", complexObj, new int[]{1, 2, 3}));

            var message = ex.getMessage();
            assertNotNull(message);
            System.out.println("Actual message: " + message);
            // The message should start with the format string prefix
            assertTrue(message.startsWith("Complex format: "), "Message should start with 'Complex format: ' but was: " + message);
            // The complex object's toString() is inserted verbatim
            assertTrue(message.contains("CustomObject{with special chars: %s, {}, []}"), "Message should contain CustomObject but was: " + message);
            // The array is converted to string using Arrays.toString()
            assertTrue(message.contains("[1, 2, 3]"), "Message should contain [1, 2, 3] but was: " + message);
        }

        @Test
        @DisplayName("handle message with more placeholders than arguments")
        void shouldHandleMorePlaceholdersThanArgs() {
            var ex = assertThrows(IllegalArgumentException.class,
                    () -> checkArgument(false, "%s %s %s", "one", "two"));

            // The remaining %s placeholder is left as-is
            var message = ex.getMessage();
            System.out.println("Actual message: " + message);
            assertTrue(message.startsWith("one two %s"), "Message should start with 'one two %s' but was: " + message);
        }

        @Test
        @DisplayName("handle message with fewer placeholders than arguments")
        void shouldHandleFewerPlaceholdersThanArgs() {
            var ex = assertThrows(IllegalArgumentException.class,
                    () -> checkArgument(false, "%s %s", "one", "two", "three"));

            // Extra arguments are appended in square brackets
            var message = ex.getMessage();
            System.out.println("Actual message: " + message);
            assertTrue(message.startsWith("one two"), "Message should start with 'one two' but was: " + message);
            assertTrue(message.contains("[three]"), "Message should contain [three] but was: " + message);
        }

        @Test
        @DisplayName("handle nested message templates")
        void shouldHandleNestedTemplates() {
            var template = "Outer{%s}";
            var inner = "Inner{%s}";
            var value = "value";

            var ex = assertThrows(IllegalArgumentException.class,
                    () -> checkArgument(false, template, String.format(inner, value)));

            // The nested template is evaluated before being passed to lenientFormat
            var message = ex.getMessage();
            System.out.println("Actual message: " + message);
            assertEquals("Outer{Inner{value}}", message);
        }
    }

    @Nested
    @DisplayName("handle concurrent state checks")
    class ConcurrentStateTest {

        private volatile boolean state = true;
        private final Object lock = new Object();

        @Test
        @DisplayName("handle concurrent state changes")
        void shouldHandleConcurrentStateChanges() {
            var threadCount = 10;
            var executor = Executors.newFixedThreadPool(threadCount);
            var futures = new ArrayList<Future<?>>();

            try {
                // Submit state-checking tasks
                for (int i = 0; i < threadCount; i++) {
                    final int iteration = i;
                    futures.add(executor.submit(() -> {
                        synchronized (lock) {
                            if (state) {
                                // Single point of potential exception
                                boolean result = state;
                                checkState(result, "State check on iteration %s", iteration);
                                state = false;
                            } else {
                                state = true;
                            }
                        }
                        return null;
                    }));
                }

                // Wait for all tasks to complete
                for (var future : futures) {
                    future.get(5, TimeUnit.SECONDS);
                }
            } catch (Exception e) {
                throw new AssertionError("Concurrent execution failed", e);
            } finally {
                executor.shutdownNow();
            }
        }

        @Test
        @DisplayName("handle concurrent error message formatting")
        void shouldHandleConcurrentMessageFormatting() {
            var threadCount = 10;
            var executor = Executors.newFixedThreadPool(threadCount);
            var futures = new ArrayList<Future<?>>();

            try {
                // Submit message formatting tasks
                for (int i = 0; i < threadCount; i++) {
                    final int iteration = i;
                    futures.add(executor.submit(() -> {
                        // Prepare message parameters before assertion
                        var messageParams = new Object[] {
                            new Object() {
                                @Override
                                public String toString() {
                                    return "Object[" + iteration + "]";
                                }
                            },
                            iteration
                        };
                        // Single point of potential exception
                        assertThrows(IllegalStateException.class, () ->
                                checkState(false, "Complex message %s with iteration %s", messageParams));
                        return null;
                    }));
                }

                // Wait for all tasks to complete
                for (var future : futures) {
                    future.get(5, TimeUnit.SECONDS);
                }
            } catch (Exception e) {
                throw new AssertionError("Concurrent execution failed", e);
            } finally {
                executor.shutdownNow();
            }
        }
    }
}
