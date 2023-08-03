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
