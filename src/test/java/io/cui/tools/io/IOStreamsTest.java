package io.cui.tools.io;

import static io.cui.tools.io.IOStreams.contentEquals;
import static io.cui.tools.io.IOStreams.toInputStream;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import io.cui.tools.support.Generators;

/**
 * @author https://github.com/apache/commons-io/blob/master/src/test/java/org/apache/commons/io/IOUtilsTestCase.java
 *
 */
class IOStreamsTest {

    private static final int FILE_SIZE = 1024 * 4 + 1;

    private final byte[] inData = Generators.generateTestData(FILE_SIZE);

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

    @Test
    @SuppressWarnings("resource")
    void shouldProvideInputStream() throws IOException {
        assertTrue(contentEquals(new ByteArrayInputStream("".getBytes(StandardCharsets.UTF_8)), toInputStream(null)));
        assertFalse(contentEquals(new ByteArrayInputStream("ABCD".getBytes(StandardCharsets.UTF_8)),
                toInputStream("ABC")));
    }

    @Test
    void testToByteArray_InputStream() throws Exception {
        try (InputStream fin = new ByteArrayInputStream(inData)) {
            final byte[] out = IOStreams.toByteArray(fin);
            assertNotNull(out);
            assertEquals(0, fin.available(), "Not all bytes were read");
            assertArrayEquals(inData, out);
        }
    }

    @Test
    void testToString_InputStream() throws Exception {
        try (InputStream fin = new ByteArrayInputStream(inData)) {
            String out = IOStreams.toString(fin, StandardCharsets.UTF_8);
            assertNotNull(out);
            assertEquals(0, fin.available(), "Not all bytes were read");
            assertArrayEquals(inData, out.getBytes());
        }
    }

}