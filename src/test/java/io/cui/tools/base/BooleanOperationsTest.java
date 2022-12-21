package io.cui.tools.base;

import static io.cui.tools.base.BooleanOperations.areAllFalse;
import static io.cui.tools.base.BooleanOperations.areAllTrue;
import static io.cui.tools.base.BooleanOperations.isAnyFalse;
import static io.cui.tools.base.BooleanOperations.isAnyTrue;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class BooleanOperationsTest {

    @Test
    void shouldDetectAnyTrue() {
        assertTrue(isAnyTrue(true));
        assertTrue(isAnyTrue(true, true));
        assertTrue(isAnyTrue(true, false));
        assertFalse(isAnyTrue(false, false));
        // Not really sensible, but defined contract -> Corner Case
        assertFalse(isAnyTrue());
        assertFalse(isAnyTrue(null));
    }

    @Test
    void shouldDetectAnyFalse() {
        assertFalse(isAnyFalse(true));
        assertTrue(isAnyFalse(true, false));
        assertTrue(isAnyFalse(false, false));
        // Not really sensible, but defined contract -> Corner Case
        assertFalse(isAnyFalse());
        assertFalse(isAnyFalse(null));
    }

    @Test
    void shouldDetectAllFalse() {
        assertFalse(areAllFalse(true));
        assertFalse(areAllFalse(true, false));
        assertFalse(areAllFalse(true, true));
        assertTrue(areAllFalse(false, false));
        // Not really sensible, but defined contract -> Corner Case
        assertFalse(areAllFalse());
        assertFalse(areAllFalse(null));
    }

    @Test
    void shouldDetectAllTrue() {
        assertTrue(areAllTrue(true));
        assertFalse(areAllTrue(true, false));
        assertTrue(areAllTrue(true, true));
        assertFalse(areAllTrue(false, false));
        // Not really sensible, but defined contract -> Corner Case
        assertTrue(areAllTrue());
        assertTrue(areAllTrue(null));
    }

    @Test
    void isValidBoolean() {
        assertFalse(assertDoesNotThrow(() -> BooleanOperations.isValidBoolean(null)));
        assertFalse(BooleanOperations.isValidBoolean(""));
        assertFalse(BooleanOperations.isValidBoolean(" "));
        assertFalse(BooleanOperations.isValidBoolean(" true "));
        assertFalse(BooleanOperations.isValidBoolean("true "));

        assertTrue(BooleanOperations.isValidBoolean("true"));
        assertTrue(BooleanOperations.isValidBoolean("false"));
        assertTrue(BooleanOperations.isValidBoolean("TrUe"));
        assertTrue(BooleanOperations.isValidBoolean("FaLsE"));
    }
}
