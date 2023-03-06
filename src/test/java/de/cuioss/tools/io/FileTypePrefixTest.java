package de.cuioss.tools.io;

import static de.cuioss.tools.io.FileTypePrefix.CLASSPATH;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class FileTypePrefixTest {

    @Test
    void removesCorrectPrefix() {
        assertEquals("foo", CLASSPATH.removePrefix("classpath:foo"));

        final var wrongValue = "klasspath:foo";
        assertEquals(wrongValue, CLASSPATH.removePrefix(wrongValue));
    }

    @Test
    void hasCorrectIdentity() {
        assertTrue(CLASSPATH.is("classpath:"));
        assertFalse(CLASSPATH.is(null));
    }

    @Test
    void toStringEqualsPrefix() {
        assertEquals(CLASSPATH.getPrefix(), CLASSPATH.toString());
    }
}