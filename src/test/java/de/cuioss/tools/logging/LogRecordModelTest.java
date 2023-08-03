package de.cuioss.tools.logging;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class LogRecordModelTest {

    private static final String PREFIX = "CUI-100";

    private final LogRecord model = LogRecordModel.builder().identifier(100).prefix("CUI").template("{}-%s").build();

    @Test
    void shouldHandlePrefix() {
        assertEquals(PREFIX, model.resolveIdentifierString());
        assertEquals(PREFIX + ": A-2", model.format("A", 2));
        // Should be reentrant
        assertEquals(PREFIX + ": A-2", model.format("A", 2));
    }

    @Test
    void shouldHandleSupplier() {
        var supplier = model.supplier("A", 2);
        assertEquals(PREFIX + ": A-2", supplier.get());
    }

}
