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
import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.Test;

class PreconditionsTest {

    private static final String SHOULD_HAVE_THROWN_EXCEPTION = "Should have thrown exception";

    private static final String MESSAGE = "message";

    private static final String MESSAGE_TEMPLATE = "message %s";

    private static final String MESSAGE_PARAMETER = "parameter";

    private static final String MESSAGE_TEMPLATE_RESULT = "message parameter";

    @Test
    void shouldHandleCheckArgument() {
        checkArgument(true);
        assertThrows(IllegalArgumentException.class, () -> checkArgument(false));

        checkArgument(true, MESSAGE);

        try {
            checkArgument(false, MESSAGE);
            fail(SHOULD_HAVE_THROWN_EXCEPTION);
        } catch (Exception e) {
            assertInstanceOf(IllegalArgumentException.class, e);
            assertEquals(MESSAGE, e.getMessage());
        }
    }

    @Test
    void shouldHandleCheckArgumentParameter() {
        checkArgument(true, MESSAGE_TEMPLATE, MESSAGE_PARAMETER);
        assertThrows(IllegalArgumentException.class, () -> checkArgument(false, MESSAGE_TEMPLATE, MESSAGE_PARAMETER));

        checkArgument(true, MESSAGE_TEMPLATE, MESSAGE_PARAMETER);

        try {
            checkArgument(false, MESSAGE_TEMPLATE, MESSAGE_PARAMETER);
            fail(SHOULD_HAVE_THROWN_EXCEPTION);
        } catch (Exception e) {
            assertInstanceOf(IllegalArgumentException.class, e);
            assertEquals(MESSAGE_TEMPLATE_RESULT, e.getMessage());
        }
    }

    @Test
    void shouldHandleCheckState() {
        checkState(true);
        assertThrows(IllegalStateException.class, () -> checkState(false));

        checkState(true, MESSAGE);

        try {
            checkState(false, MESSAGE);
            fail(SHOULD_HAVE_THROWN_EXCEPTION);
        } catch (Exception e) {
            assertInstanceOf(IllegalStateException.class, e);
            assertEquals(MESSAGE, e.getMessage());
        }
    }

    @Test
    void shouldHandleCheckStateParameter() {
        checkState(true, MESSAGE_TEMPLATE, MESSAGE_PARAMETER);
        assertThrows(IllegalStateException.class, () -> checkState(false, MESSAGE_TEMPLATE, MESSAGE_PARAMETER));

        checkState(true, MESSAGE_TEMPLATE, MESSAGE_PARAMETER);

        try {
            checkState(false, MESSAGE_TEMPLATE, MESSAGE_PARAMETER);
            fail(SHOULD_HAVE_THROWN_EXCEPTION);
        } catch (Exception e) {
            assertInstanceOf(IllegalStateException.class, e);
            assertEquals(MESSAGE_TEMPLATE_RESULT, e.getMessage());
        }
    }

}
