package de.icw.util.formatting;

import org.junit.jupiter.api.Test;

import de.icw.util.support.ObjectMethodsAsserts;

/**
 * FIXME efischer: Provide some sensible unit-tests
 */
class SimpleFormatterTest {

    @Test
    void shouldImplementObjectContracts() {
        ObjectMethodsAsserts.assertNiceObject(new SimpleFormatter.Builder().ignoreMissingValues().separatesBy("-"));
    }
}
