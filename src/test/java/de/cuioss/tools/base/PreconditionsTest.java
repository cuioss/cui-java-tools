package de.cuioss.tools.base;

import static de.cuioss.tools.base.Preconditions.checkArgument;
import static de.cuioss.tools.base.Preconditions.checkState;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
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
            assertTrue(e instanceof IllegalArgumentException);
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
            assertTrue(e instanceof IllegalArgumentException);
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
            assertTrue(e instanceof IllegalStateException);
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
            assertTrue(e instanceof IllegalStateException);
            assertEquals(MESSAGE_TEMPLATE_RESULT, e.getMessage());
        }
    }

}
