package de.cuioss.tools.lang;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

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
        assertFalse(MoreArrays.isEmpty(new boolean[] { true }));
    }

    @Test
    void shouldDetermineEmptyFloatArray() {
        assertTrue(MoreArrays.isEmpty((float[]) null));
        assertTrue(MoreArrays.isEmpty(new float[0]));
        assertFalse(MoreArrays.isEmpty(new float[] { 1.0f }));
    }

    @Test
    void shouldDetermineEmptyDoubleArray() {
        assertTrue(MoreArrays.isEmpty((double[]) null));
        assertTrue(MoreArrays.isEmpty(new double[0]));
        assertFalse(MoreArrays.isEmpty(new double[] { 1.0d }));
    }

    @Test
    void shouldDetermineEmptyIntArray() {
        assertTrue(MoreArrays.isEmpty((int[]) null));
        assertTrue(MoreArrays.isEmpty(new int[0]));
        assertFalse(MoreArrays.isEmpty(new int[] { 1 }));
    }

    @Test
    void shouldDetermineEmptyLongArray() {
        assertTrue(MoreArrays.isEmpty((long[]) null));
        assertTrue(MoreArrays.isEmpty(new long[0]));
        assertFalse(MoreArrays.isEmpty(new long[] { 1l }));
    }

    @Test
    void shouldDetermineEmptyShortArray() {
        assertTrue(MoreArrays.isEmpty((short[]) null));
        assertTrue(MoreArrays.isEmpty(new short[0]));
        assertFalse(MoreArrays.isEmpty(new short[] { 1 }));
    }

}
