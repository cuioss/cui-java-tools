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
package de.cuioss.tools.lang;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MoreArraysTest {

    @Test
    void shouldDetermineEmptyByteArray() {
        assertTrue(MoreArrays.isEmpty((byte[]) null));
        assertTrue(MoreArrays.isEmpty(new byte[0]));
        assertFalse(MoreArrays.isEmpty("hello".getBytes()));
    }

    @Test
    void shouldDetermineEmptyCharArray() {
        assertTrue(MoreArrays.isEmpty((char[]) null));
        assertTrue(MoreArrays.isEmpty(new char[0]));
        assertFalse(MoreArrays.isEmpty("hello".toCharArray()));
    }

    @Test
    void shouldDetermineEmptyBooleanArray() {
        assertTrue(MoreArrays.isEmpty((boolean[]) null));
        assertTrue(MoreArrays.isEmpty(new boolean[0]));
        assertFalse(MoreArrays.isEmpty(new boolean[]{true}));
    }

    @Test
    void shouldDetermineEmptyFloatArray() {
        assertTrue(MoreArrays.isEmpty((float[]) null));
        assertTrue(MoreArrays.isEmpty(new float[0]));
        assertFalse(MoreArrays.isEmpty(new float[]{1.0f}));
    }

    @Test
    void shouldDetermineEmptyDoubleArray() {
        assertTrue(MoreArrays.isEmpty((double[]) null));
        assertTrue(MoreArrays.isEmpty(new double[0]));
        assertFalse(MoreArrays.isEmpty(new double[]{1.0d}));
    }

    @Test
    void shouldDetermineEmptyIntArray() {
        assertTrue(MoreArrays.isEmpty((int[]) null));
        assertTrue(MoreArrays.isEmpty(new int[0]));
        assertFalse(MoreArrays.isEmpty(new int[]{1}));
    }

    @Test
    void shouldDetermineEmptyLongArray() {
        assertTrue(MoreArrays.isEmpty((long[]) null));
        assertTrue(MoreArrays.isEmpty(new long[0]));
        assertFalse(MoreArrays.isEmpty(new long[]{1L}));
    }

    @Test
    void shouldDetermineEmptyShortArray() {
        assertTrue(MoreArrays.isEmpty((short[]) null));
        assertTrue(MoreArrays.isEmpty(new short[0]));
        assertFalse(MoreArrays.isEmpty(new short[]{1}));
    }

}
