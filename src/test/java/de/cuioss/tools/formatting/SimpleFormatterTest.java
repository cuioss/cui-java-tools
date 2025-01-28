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
package de.cuioss.tools.formatting;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import de.cuioss.tools.support.ObjectMethodsAsserts;
import org.junit.jupiter.api.Test;

class SimpleFormatterTest {

    @Test
    void shouldImplementObjectContracts() {
        ObjectMethodsAsserts.assertNiceObject(SimpleFormatter.builder());
        ObjectMethodsAsserts.assertNiceObject(SimpleFormatter.builder().ignoreMissingValues());
        ObjectMethodsAsserts.assertNiceObject(SimpleFormatter.builder().ignoreMissingValues().separatesBy("-"));
    }

    @Test
    void shouldFormatOnMissingElements() {
        final var formatted = SimpleFormatter.builder().ignoreMissingValues().separatesBy(", ").format("a", null, "c");

        assertEquals("a, c", formatted);
    }

    @Test
    void shouldNotFormatIfElementsAreMissing() {

        final var formatted = SimpleFormatter.builder().skipResultIfAnyValueIsMissing().separatesBy(" - ")
                .formatParentheses("a", "b", null, "d");

        assertNull(formatted);

    }

    @Test
    void shouldFormatParentheses() {
        final var formatted = SimpleFormatter.builder().skipResultIfAnyValueIsMissing().separatesBy(" ")
                .formatParentheses("a", "b", "c", "d");
        assertEquals("(a b c d)", formatted);
    }
}
