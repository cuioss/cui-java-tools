/*
 * Copyright © 2025 CUI-OpenSource-Software (info@cuioss.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.tools.collect;

import de.cuioss.tools.support.ObjectMethodsAsserts;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static de.cuioss.tools.collect.PartialArrayList.emptyList;
import static de.cuioss.tools.collect.PartialArrayList.of;
import static de.cuioss.tools.support.Generators.randomInt;
import static de.cuioss.tools.support.Generators.randomStrings;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PartialArrayListTest {

    private static final int DEFAULT_SIZE = 10;

    @Test
    void shouldHandleEmptyList() {
        assertTrue(emptyList().isEmpty());
        assertFalse(emptyList().isMoreAvailable());
        assertTrue(of(null, DEFAULT_SIZE).isEmpty());
        assertFalse(of(null, DEFAULT_SIZE).isMoreAvailable());
        assertTrue(of(Collections.emptyList(), DEFAULT_SIZE).isEmpty());
        assertFalse(of(Collections.emptyList(), DEFAULT_SIZE).isMoreAvailable());
    }

    @Test
    void shouldHandleSmallLists() {
        assertFalse(of(randomStrings(DEFAULT_SIZE), DEFAULT_SIZE).isEmpty());
        assertEquals(DEFAULT_SIZE, of(randomStrings(DEFAULT_SIZE), DEFAULT_SIZE).size());
        assertFalse(of(randomStrings(DEFAULT_SIZE), DEFAULT_SIZE).isMoreAvailable());
    }

    @Test
    void shouldHandleLargeLists() {
        // Larger List
        var count = randomInt(1, 256);
        var bigger = count + 1;

        assertFalse(of(randomStrings(bigger), count).isEmpty());
        assertEquals(count, of(randomStrings(bigger), count).size());
        assertTrue(of(randomStrings(bigger), count).isMoreAvailable());
    }

    @Test
    void shouldImplementObjectContracts() {
        ObjectMethodsAsserts.assertNiceObject(of(randomStrings(4), 4));
    }
}
