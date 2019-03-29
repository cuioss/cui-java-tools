package de.icw.util.io;

import static de.icw.util.io.IOStreams.contentEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

/**
 * Taken from
 * https://github.com/apache/commons-io/blob/master/src/test/java/org/apache/commons/io/IOUtilsTestCase.java
 *
 */
class IOStreamsTest {

    @Test
    void testContentEquals_InputStream_InputStream() throws Exception {
        ByteArrayInputStream input1 = new ByteArrayInputStream("".getBytes(StandardCharsets.UTF_8));
        assertTrue(contentEquals(input1, input1));
        input1 = new ByteArrayInputStream("ABC".getBytes(StandardCharsets.UTF_8));
        assertTrue(contentEquals(input1, input1));
        assertTrue(contentEquals(new ByteArrayInputStream("".getBytes(StandardCharsets.UTF_8)),
                new ByteArrayInputStream("".getBytes(StandardCharsets.UTF_8))));
        assertTrue(contentEquals(
                new BufferedInputStream(new ByteArrayInputStream("".getBytes(StandardCharsets.UTF_8))),
                new BufferedInputStream(
                        new ByteArrayInputStream("".getBytes(StandardCharsets.UTF_8)))));
        assertTrue(contentEquals(new ByteArrayInputStream("ABC".getBytes(StandardCharsets.UTF_8)),
                new ByteArrayInputStream("ABC".getBytes(StandardCharsets.UTF_8))));
        assertFalse(contentEquals(new ByteArrayInputStream("ABCD".getBytes(StandardCharsets.UTF_8)),
                new ByteArrayInputStream("ABC".getBytes(StandardCharsets.UTF_8))));
        assertFalse(contentEquals(new ByteArrayInputStream("ABC".getBytes(StandardCharsets.UTF_8)),
                new ByteArrayInputStream("ABCD".getBytes(StandardCharsets.UTF_8))));
    }

    @Test
    void testContentEquals_Reader_Reader() throws Exception {
        StringReader input1 = new StringReader("");
        assertTrue(contentEquals(input1, input1));

        input1 = new StringReader("ABC");
        assertTrue(contentEquals(input1, input1));
        assertTrue(contentEquals(new StringReader(""), new StringReader("")));
        assertTrue(contentEquals(new BufferedReader(new StringReader("")), new BufferedReader(new StringReader(""))));
        assertTrue(contentEquals(new StringReader("ABC"), new StringReader("ABC")));
        assertFalse(contentEquals(new StringReader("ABCD"), new StringReader("ABC")));
        assertFalse(contentEquals(new StringReader("ABC"), new StringReader("ABCD")));
    }

}
