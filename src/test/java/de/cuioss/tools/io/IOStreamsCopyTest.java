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
package de.cuioss.tools.io;

import static de.cuioss.tools.io.IOStreams.copyLarge;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import de.cuioss.tools.io.support.NullInputStream;
import de.cuioss.tools.io.support.NullOutputStream;
import de.cuioss.tools.io.support.NullReader;
import de.cuioss.tools.io.support.NullWriter;
import de.cuioss.tools.io.support.YellOnCloseInputStream;
import de.cuioss.tools.io.support.YellOnFlushAndCloseOutputStream;
import de.cuioss.tools.support.Generators;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.CharArrayReader;
import java.io.CharArrayWriter;
import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * @author <a href="https://github.com/apache/commons-io/blob/master/src/test/java/org/apache/commons/io/IOUtilsCopyTestCase.java">...</a>
 *
 */
@SuppressWarnings("resource")
class IOStreamsCopyTest {

    /*
     * NOTE this is not particularly beautiful code. A better way to check for flush
     * and close status would be to implement "trojan horse" wrapper implementations
     * of the various stream classes, which set a flag when relevant methods are
     * called. (JT)
     */

    private static final int FILE_SIZE = 1024 * 4 + 1;

    private final byte[] inData = Generators.generateTestData(FILE_SIZE);

    /*
     * Note: this is not particularly beautiful code. A better way to check for
     * flush and close status would be to implement "trojan horse" wrapper
     * implementations of the various stream classes, which set a flag when relevant
     * methods are called. (JT)
     */

    private char[] carr = null;

    private byte[] iarr = null;

    @BeforeEach
    void setUp() {
        // Create and init a byte array as input data
        iarr = new byte[200];
        Arrays.fill(iarr, (byte) -1);
        for (var i = 0; i < 80; i++) {
            iarr[i] = (byte) i;
        }
        carr = new char[200];
        Arrays.fill(carr, (char) -1);
        for (var i = 0; i < 80; i++) {
            carr[i] = (char) i;
        }
    }

    // -----------------------------------------------------------------------
    @Test
    void copyInputStreamToOutputStream() throws Exception {
        InputStream in = new ByteArrayInputStream(inData);
        in = new YellOnCloseInputStream(in);

        final var baout = new ByteArrayOutputStream();
        final OutputStream out = new YellOnFlushAndCloseOutputStream(baout, false, true);

        final var count = IOStreams.copy(in, out);

        assertEquals(0, in.available(), "Not all bytes were read");
        assertEquals(inData.length, baout.size(), "Sizes differ");
        assertArrayEquals(inData, baout.toByteArray(), "Content differs");
        assertEquals(inData.length, count);
    }

    /*
     * Test Copying file > 2GB - see issue# IO-84
     */
    @Test
    void copyInputStreamToOutputStreamIO84() throws Exception {
        final var size = (long) Integer.MAX_VALUE + (long) 1;
        final InputStream in = new NullInputStream(size);
        final OutputStream out = new NullOutputStream();

        // Test copy() method
        assertEquals(-1, IOStreams.copy(in, out));

        // reset the input
        in.close();

        // Test copyLarge() method
        assertEquals(size, IOStreams.copyLarge(in, out), "copyLarge()");
    }

    @Test
    void copyInputStreamToOutputStreamNullIn() throws Exception {
        final OutputStream out = new ByteArrayOutputStream();
        assertThrows(NullPointerException.class, () ->
            IOStreams.copy(null, out));
    }

    @Test
    void copyInputStreamToOutputStreamNullOut() throws Exception {
        final InputStream in = new ByteArrayInputStream(inData);
        assertThrows(NullPointerException.class, () ->
            IOStreams.copy(in, null));
    }

    @Test
    void copyInputStreamToOutputStreamWithBufferSize() throws Exception {
        testCopy_inputStreamToOutputStreamWithBufferSize(1);
        testCopy_inputStreamToOutputStreamWithBufferSize(2);
        testCopy_inputStreamToOutputStreamWithBufferSize(4);
        testCopy_inputStreamToOutputStreamWithBufferSize(8);
        testCopy_inputStreamToOutputStreamWithBufferSize(16);
        testCopy_inputStreamToOutputStreamWithBufferSize(32);
        testCopy_inputStreamToOutputStreamWithBufferSize(64);
        testCopy_inputStreamToOutputStreamWithBufferSize(128);
        testCopy_inputStreamToOutputStreamWithBufferSize(256);
        testCopy_inputStreamToOutputStreamWithBufferSize(512);
        testCopy_inputStreamToOutputStreamWithBufferSize(1024);
        testCopy_inputStreamToOutputStreamWithBufferSize(2048);
        testCopy_inputStreamToOutputStreamWithBufferSize(4096);
        testCopy_inputStreamToOutputStreamWithBufferSize(8192);
        testCopy_inputStreamToOutputStreamWithBufferSize(16384);
    }

    private void testCopy_inputStreamToOutputStreamWithBufferSize(final int bufferSize) throws Exception {
        InputStream in = new ByteArrayInputStream(inData);
        in = new YellOnCloseInputStream(in);

        final var baout = new ByteArrayOutputStream();
        final OutputStream out = new YellOnFlushAndCloseOutputStream(baout, false, true);

        final var count = IOStreams.copy(in, out, bufferSize);

        assertEquals(0, in.available(), "Not all bytes were read");
        assertEquals(inData.length, baout.size(), "Sizes differ");
        assertArrayEquals(inData, baout.toByteArray(), "Content differs");
        assertEquals(inData.length, count);
    }

    // -----------------------------------------------------------------------
    @Test
    void copyInputStreamToWriterEncoding() throws Exception {
        InputStream in = new ByteArrayInputStream(inData);
        in = new YellOnCloseInputStream(in);

        final var baout = new ByteArrayOutputStream();
        final var out = new YellOnFlushAndCloseOutputStream(baout, true, true);
        final Writer writer = new OutputStreamWriter(baout, StandardCharsets.US_ASCII);

        IOStreams.copy(in, writer, "UTF8");
        out.off();
        writer.flush();

        assertEquals(0, in.available(), "Not all bytes were read");
        var bytes = baout.toByteArray();
        bytes = new String(bytes, StandardCharsets.UTF_8).getBytes(StandardCharsets.US_ASCII);
        assertArrayEquals(inData, bytes, "Content differs");
    }

    @Test
    void copyInputStreamToWriterEncodingNullEncoding() throws Exception {
        InputStream in = new ByteArrayInputStream(inData);
        in = new YellOnCloseInputStream(in);

        final var baout = new ByteArrayOutputStream();
        final var out = new YellOnFlushAndCloseOutputStream(baout, true, true);
        final Writer writer = new OutputStreamWriter(baout, StandardCharsets.US_ASCII);

        IOStreams.copy(in, writer, (String) null);
        out.off();
        writer.flush();

        assertEquals(0, in.available(), "Not all bytes were read");
        assertEquals(inData.length, baout.size(), "Sizes differ");
        assertArrayEquals(inData, baout.toByteArray(), "Content differs");
    }

    @Test
    void copyInputStreamToWriterEncodingNullIn() throws Exception {
        final var baout = new ByteArrayOutputStream();
        final OutputStream out = new YellOnFlushAndCloseOutputStream(baout, true, true);
        final Writer writer = new OutputStreamWriter(out, StandardCharsets.US_ASCII);
        assertThrows(NullPointerException.class, () ->
            IOStreams.copy(null, writer, "UTF8"));
    }

    @Test
    void copyInputStreamToWriterEncodingNullOut() throws Exception {
        final InputStream in = new ByteArrayInputStream(inData);
        assertThrows(NullPointerException.class, () ->
            IOStreams.copy(in, null, "UTF8"));
    }

    // -----------------------------------------------------------------------
    @Test
    void copyReaderToOutputStreamEncoding() throws Exception {
        InputStream in = new ByteArrayInputStream(inData);
        in = new YellOnCloseInputStream(in);
        final Reader reader = new InputStreamReader(in, StandardCharsets.US_ASCII);

        final var baout = new ByteArrayOutputStream();
        final OutputStream out = new YellOnFlushAndCloseOutputStream(baout, false, true);

        IOStreams.copy(reader, out, "UTF16");
        // note: this method *does* flush.
        // note: we don't flush here; this IOUtils method does it for us

        var bytes = baout.toByteArray();
        bytes = new String(bytes, StandardCharsets.UTF_16).getBytes(StandardCharsets.US_ASCII);
        assertArrayEquals(inData, bytes, "Content differs");
    }

    @Test
    void copyReaderToOutputStreamEncodingNullEncoding() throws Exception {
        InputStream in = new ByteArrayInputStream(inData);
        in = new YellOnCloseInputStream(in);
        final Reader reader = new InputStreamReader(in, StandardCharsets.US_ASCII);

        final var baout = new ByteArrayOutputStream();
        final OutputStream out = new YellOnFlushAndCloseOutputStream(baout, false, true);

        IOStreams.copy(reader, out, (String) null);
        // note: this method *does* flush.
        // note: we don't flush here; this IOUtils method does it for us

        assertEquals(inData.length, baout.size(), "Sizes differ");
        assertArrayEquals(inData, baout.toByteArray(), "Content differs");
    }

    @Test
    void copyReaderToOutputStreamEncodingNullIn() throws Exception {
        final var baout = new ByteArrayOutputStream();
        final OutputStream out = new YellOnFlushAndCloseOutputStream(baout, true, true);
        assertThrows(NullPointerException.class, () ->
            IOStreams.copy(null, out, "UTF16"));
    }

    @Test
    void copyReaderToOutputStreamEncodingNullOut() throws Exception {
        InputStream in = new ByteArrayInputStream(inData);
        in = new YellOnCloseInputStream(in);
        final Reader reader = new InputStreamReader(in, StandardCharsets.US_ASCII);
        assertThrows(NullPointerException.class, () ->
            IOStreams.copy(reader, null, "UTF16"));
    }

    // -----------------------------------------------------------------------
    @Test
    void copyReaderToWriter() throws Exception {
        InputStream in = new ByteArrayInputStream(inData);
        in = new YellOnCloseInputStream(in);
        final Reader reader = new InputStreamReader(in, StandardCharsets.US_ASCII);

        final var baout = new ByteArrayOutputStream();
        final var out = new YellOnFlushAndCloseOutputStream(baout, true, true);
        final Writer writer = new OutputStreamWriter(baout, StandardCharsets.US_ASCII);

        final var count = IOStreams.copy(reader, writer);
        out.off();
        writer.flush();
        assertEquals(inData.length, count, "The number of characters returned by copy is wrong");
        assertEquals(inData.length, baout.size(), "Sizes differ");
        assertArrayEquals(inData, baout.toByteArray(), "Content differs");
    }

    /*
     * Test Copying file > 2GB - see issue# IO-84
     */
    @Test
    void copyReaderToWriterIO84() throws Exception {
        final var size = (long) Integer.MAX_VALUE + (long) 1;
        final Reader reader = new NullReader(size);
        final Writer writer = new NullWriter();

        // Test copy() method
        assertEquals(-1, IOStreams.copy(reader, writer));

        // reset the input
        reader.close();

        // Test copyLarge() method
        assertEquals(size, IOStreams.copyLarge(reader, writer));

    }

    @Test
    void copyReaderToWriterNullIn() throws Exception {
        final var baout = new ByteArrayOutputStream();
        final OutputStream out = new YellOnFlushAndCloseOutputStream(baout, true, true);
        final Writer writer = new OutputStreamWriter(out, StandardCharsets.US_ASCII);
        assertThrows(NullPointerException.class, () ->
            IOStreams.copy(null, writer));
    }

    @Test
    void copyReaderToWriterNullOut() throws Exception {
        InputStream in = new ByteArrayInputStream(inData);
        in = new YellOnCloseInputStream(in);
        final Reader reader = new InputStreamReader(in, StandardCharsets.US_ASCII);
        assertThrows(NullPointerException.class, () ->
            IOStreams.copy(reader, null));
    }

    @Test
    void copyLargeCharExtraLength() throws IOException {
        CharArrayReader is = null;
        CharArrayWriter os = null;
        try {
            // Create streams
            is = new CharArrayReader(carr);
            os = new CharArrayWriter();

            // Test our copy method
            // for extra length, it reads till EOF
            assertEquals(200, copyLarge(is, os, 0, 2000));
            final var oarr = os.toCharArray();

            // check that output length is correct
            assertEquals(200, oarr.length);
            // check that output data corresponds to input data
            assertEquals(1, oarr[1]);
            assertEquals(79, oarr[79]);
            assertEquals((char) -1, oarr[80]);

        } finally {
            closeQuietly(is);
            closeQuietly(os);
        }
    }

    /**
     * @param is
     */
    private void closeQuietly(Closeable is) {
        try {
            is.close();
        } catch (IOException e) {
            // Test only
        }

    }

    @Test
    void copyLargeCharFullLength() throws IOException {
        CharArrayReader is = null;
        CharArrayWriter os = null;
        try {
            // Create streams
            is = new CharArrayReader(carr);
            os = new CharArrayWriter();

            // Test our copy method
            assertEquals(200, copyLarge(is, os, 0, -1));
            final var oarr = os.toCharArray();

            // check that output length is correct
            assertEquals(200, oarr.length);
            // check that output data corresponds to input data
            assertEquals(1, oarr[1]);
            assertEquals(79, oarr[79]);
            assertEquals((char) -1, oarr[80]);

        } finally {
            closeQuietly(is);
            closeQuietly(os);
        }
    }

    @Test
    void copyLargeCharNoSkip() throws IOException {
        CharArrayReader is = null;
        CharArrayWriter os = null;
        try {
            // Create streams
            is = new CharArrayReader(carr);
            os = new CharArrayWriter();

            // Test our copy method
            assertEquals(100, copyLarge(is, os, 0, 100));
            final var oarr = os.toCharArray();

            // check that output length is correct
            assertEquals(100, oarr.length);
            // check that output data corresponds to input data
            assertEquals(1, oarr[1]);
            assertEquals(79, oarr[79]);
            assertEquals((char) -1, oarr[80]);

        } finally {
            closeQuietly(is);
            closeQuietly(os);
        }
    }

    @Test
    void copyLargeCharSkip() throws IOException {
        CharArrayReader is = null;
        CharArrayWriter os = null;
        try {
            // Create streams
            is = new CharArrayReader(carr);
            os = new CharArrayWriter();

            // Test our copy method
            assertEquals(100, copyLarge(is, os, 10, 100));
            final var oarr = os.toCharArray();

            // check that output length is correct
            assertEquals(100, oarr.length);
            // check that output data corresponds to input data
            assertEquals(11, oarr[1]);
            assertEquals(79, oarr[69]);
            assertEquals((char) -1, oarr[70]);

        } finally {
            closeQuietly(is);
            closeQuietly(os);
        }
    }

    @Test
    void copyLargeCharSkipInvalid() throws IOException {
        CharArrayReader is = null;
        CharArrayWriter os = null;
        try {
            // Create streams
            is = new CharArrayReader(carr);
            os = new CharArrayWriter();

            // Test our copy method
            copyLarge(is, os, 1000, 100);
            fail("Should have thrown EOFException");
        } catch (final EOFException ignore) {
        } finally {
            closeQuietly(is);
            closeQuietly(os);
        }
    }

    @Test
    void copyLargeExtraLength() throws IOException {
        ByteArrayInputStream is = null;
        ByteArrayOutputStream os = null;
        try {
            // Create streams
            is = new ByteArrayInputStream(iarr);
            os = new ByteArrayOutputStream();

            // Test our copy method
            // for extra length, it reads till EOF
            assertEquals(200, copyLarge(is, os, 0, 2000));
            final var oarr = os.toByteArray();

            // check that output length is correct
            assertEquals(200, oarr.length);
            // check that output data corresponds to input data
            assertEquals(1, oarr[1]);
            assertEquals(79, oarr[79]);
            assertEquals(-1, oarr[80]);

        } finally {
            closeQuietly(is);
            closeQuietly(os);
        }
    }

    @Test
    void copyLargeFullLength() throws IOException {
        ByteArrayInputStream is = null;
        ByteArrayOutputStream os = null;
        try {
            // Create streams
            is = new ByteArrayInputStream(iarr);
            os = new ByteArrayOutputStream();

            // Test our copy method
            assertEquals(200, copyLarge(is, os, 0, -1));
            final var oarr = os.toByteArray();

            // check that output length is correct
            assertEquals(200, oarr.length);
            // check that output data corresponds to input data
            assertEquals(1, oarr[1]);
            assertEquals(79, oarr[79]);
            assertEquals(-1, oarr[80]);

        } finally {
            closeQuietly(is);
            closeQuietly(os);
        }
    }

    @Test
    void copyLargeNoSkip() throws IOException {
        ByteArrayInputStream is = null;
        ByteArrayOutputStream os = null;
        try {
            // Create streams
            is = new ByteArrayInputStream(iarr);
            os = new ByteArrayOutputStream();

            // Test our copy method
            assertEquals(100, copyLarge(is, os, 0, 100));
            final var oarr = os.toByteArray();

            // check that output length is correct
            assertEquals(100, oarr.length);
            // check that output data corresponds to input data
            assertEquals(1, oarr[1]);
            assertEquals(79, oarr[79]);
            assertEquals(-1, oarr[80]);

        } finally {
            closeQuietly(is);
            closeQuietly(os);
        }
    }

    @Test
    void copyLargeSkip() throws IOException {
        ByteArrayInputStream is = null;
        ByteArrayOutputStream os = null;
        try {
            // Create streams
            is = new ByteArrayInputStream(iarr);
            os = new ByteArrayOutputStream();

            // Test our copy method
            assertEquals(100, copyLarge(is, os, 10, 100));
            final var oarr = os.toByteArray();

            // check that output length is correct
            assertEquals(100, oarr.length);
            // check that output data corresponds to input data
            assertEquals(11, oarr[1]);
            assertEquals(79, oarr[69]);
            assertEquals(-1, oarr[70]);

        } finally {
            closeQuietly(is);
            closeQuietly(os);
        }
    }

    @Test
    void copyLargeSkipInvalid() throws IOException {
        ByteArrayInputStream is = null;
        ByteArrayOutputStream os = null;
        try {
            // Create streams
            is = new ByteArrayInputStream(iarr);
            os = new ByteArrayOutputStream();

            // Test our copy method
            copyLarge(is, os, 1000, 100);
            fail("Should have thrown EOFException");
        } catch (final EOFException ignore) {
        } finally {
            closeQuietly(is);
            closeQuietly(os);
        }
    }
}
