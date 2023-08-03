package de.cuioss.tools.formatting;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

import de.cuioss.tools.support.ObjectMethodsAsserts;

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
