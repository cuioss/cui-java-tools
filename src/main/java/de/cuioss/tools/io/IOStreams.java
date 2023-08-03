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

import static de.cuioss.tools.string.MoreStrings.nullToEmpty;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.StringWriter;
import java.io.Writer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import de.cuioss.tools.base.Preconditions;
import lombok.experimental.UtilityClass;

/**
 * Provides a number of utilities in context {@link InputStream} and
 * {@link OutputStream}s. The content is inspired / copied from
 * org.apache.commons.io.IOUtils
 *
 * @author Oliver Wolff
 *
 */
@UtilityClass
public class IOStreams {

    private static final String ACTUAL = " actual: ";

    private static final String SKIP_COUNT_MUST_BE_NON_NEGATIVE_ACTUAL = "Skip count must be non-negative, actual: ";

    /**
     * Represents the end-of-file (or stream).
     */
    public static final int EOF = -1;

    /**
     * The default buffer size ({@value}) to use in copy methods.
     */
    public static final int DEFAULT_BUFFER_SIZE = 1024 * 4;

    /**
     * The default buffer size to use for the skip() methods.
     */
    private static final int SKIP_BUFFER_SIZE = 2048;

    // Allocated in the relevant skip method if necessary.
    /*
     * These buffers are static and are shared between threads. This is possible
     * because the buffers are write-only - the contents are never read.
     *
     * N.B. there is no need to synchronize when creating these because: - we don't
     * care if the buffer is created multiple times (the data is ignored) - we
     * always use the same size buffer, so if it is recreated it will still be OK
     * (if the buffer size were variable, we would need to sync. to ensure some
     * other thread did not create a smaller one)
     */
    private static char[] skipCharBuffer;
    private static byte[] skipByteBuffer;

    /**
     * Compares the contents of two Streams to determine if they are equal or not.
     * <p>
     * This method buffers the input internally using
     * <code>BufferedInputStream</code> if they are not already buffered.
     *
     * @param input1 the first stream
     * @param input2 the second stream
     * @return true if the content of the streams are equal or they both don't
     *         exist, false otherwise
     * @throws NullPointerException if either input is null
     * @throws IOException          if an I/O error occurs
     */
    public static boolean contentEquals(InputStream input1, InputStream input2) throws IOException {
        if (input1 == input2) {
            return true;
        }
        if (!(input1 instanceof BufferedInputStream)) {
            input1 = new BufferedInputStream(input1);
        }
        if (!(input2 instanceof BufferedInputStream)) {
            input2 = new BufferedInputStream(input2);
        }

        var ch = input1.read();
        while (EOF != ch) {
            final var ch2 = input2.read();
            if (ch != ch2) {
                return false;
            }
            ch = input1.read();
        }

        final var ch2 = input2.read();
        return ch2 == EOF;
    }

    /**
     * Compares the contents of two Readers to determine if they are equal or not.
     * <p>
     * This method buffers the input internally using <code>BufferedReader</code> if
     * they are not already buffered.
     *
     * @param input1 the first reader
     * @param input2 the second reader
     * @return true if the content of the readers are equal or they both don't
     *         exist, false otherwise
     * @throws NullPointerException if either input is null
     * @throws IOException          if an I/O error occurs
     */
    public static boolean contentEquals(Reader input1, Reader input2) throws IOException {
        if (input1 == input2) {
            return true;
        }

        input1 = toBufferedReader(input1);
        input2 = toBufferedReader(input2);

        var ch = input1.read();
        while (EOF != ch) {
            final var ch2 = input2.read();
            if (ch != ch2) {
                return false;
            }
            ch = input1.read();
        }

        final var ch2 = input2.read();
        return ch2 == EOF;
    }

    /**
     * Wraps an {@link ByteArrayInputStream} around a given {@link String} assuming
     * {@link StandardCharsets#UTF_8}
     *
     * @param input to be wrapped, may be null or empty
     * @return the created {@link InputStream}
     */
    public static InputStream toInputStream(String input) {
        return new ByteArrayInputStream(nullToEmpty(input).getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Gets the contents of an <code>InputStream</code> as a String using the
     * specified character encoding.
     * <p>
     * This method buffers the input internally, so there is no need to use a
     * <code>BufferedInputStream</code>.
     * </p>
     *
     * @param input the <code>InputStream</code> to read from, using UTF-8 encoding.
     * @return the requested String
     * @throws NullPointerException if the input is null
     * @throws IOException          if an I/O error occurs
     */
    public static String toString(final InputStream input) throws IOException {
        return toString(input, StandardCharsets.UTF_8);
    }

    /**
     * Gets the contents of an <code>InputStream</code> as a String using the
     * specified character encoding.
     * <p>
     * This method buffers the input internally, so there is no need to use a
     * <code>BufferedInputStream</code>.
     * </p>
     *
     * @param input    the <code>InputStream</code> to read from
     * @param encoding the encoding to use, null means platform default
     * @return the requested String
     * @throws IllegalArgumentException if the input is null
     * @throws IOException              if an I/O error occurs
     */
    public static String toString(final InputStream input, final Charset encoding) throws IOException {
        Preconditions.checkArgument(null != input, "InputStream must not be null");
        try (final var sw = new StringWriter()) {
            copy(input, sw, encoding);
            return sw.toString();
        }
    }

    /**
     * Returns the given reader if it is a {@link BufferedReader}, otherwise creates
     * a BufferedReader from the given reader.
     *
     * @param reader the reader to wrap or return (not null)
     * @return the given reader or a new {@link BufferedReader} for the given reader
     * @throws NullPointerException if the input parameter is null
     */
    public static BufferedReader toBufferedReader(final Reader reader) {
        return reader instanceof BufferedReader ? (BufferedReader) reader : new BufferedReader(reader);
    }

    // copy from InputStream
    // -----------------------------------------------------------------------

    /**
     * Copies bytes from an <code>InputStream</code> to an
     * <code>OutputStream</code>.
     * <p>
     * This method buffers the input internally, so there is no need to use a
     * <code>BufferedInputStream</code>.
     * <p>
     * Large streams (over 2GB) will return a bytes copied value of <code>-1</code>
     * after the copy has completed since the correct number of bytes cannot be
     * returned as an int. For large streams use the
     * <code>copyLarge(InputStream, OutputStream)</code> method.
     *
     * @param input  the <code>InputStream</code> to read from
     * @param output the <code>OutputStream</code> to write to
     * @return the number of bytes copied, or -1 if &gt; Integer.MAX_VALUE
     * @throws NullPointerException if the input or output is null
     * @throws IOException          if an I/O error occurs
     *
     */
    public static int copy(final InputStream input, final OutputStream output) throws IOException {
        final var count = copyLarge(input, output);
        if (count > Integer.MAX_VALUE) {
            return -1;
        }
        return (int) count;
    }

    /**
     * Copies bytes from an <code>InputStream</code> to an <code>OutputStream</code>
     * using an internal buffer of the given size.
     * <p>
     * This method buffers the input internally, so there is no need to use a
     * <code>BufferedInputStream</code>.
     * <p>
     *
     * @param input      the <code>InputStream</code> to read from
     * @param output     the <code>OutputStream</code> to write to
     * @param bufferSize the bufferSize used to copy from the input to the output
     * @return the number of bytes copied
     * @throws NullPointerException if the input or output is null
     * @throws IOException          if an I/O error occurs
     *
     */
    public static long copy(final InputStream input, final OutputStream output, final int bufferSize)
            throws IOException {
        return copyLarge(input, output, new byte[bufferSize]);
    }

    /**
     * Copies bytes from a large (over 2GB) <code>InputStream</code> to an
     * <code>OutputStream</code>.
     * <p>
     * This method buffers the input internally, so there is no need to use a
     * <code>BufferedInputStream</code>.
     * <p>
     * The buffer size is given by {@link #DEFAULT_BUFFER_SIZE}.
     *
     * @param input  the <code>InputStream</code> to read from
     * @param output the <code>OutputStream</code> to write to
     * @return the number of bytes copied
     * @throws NullPointerException if the input or output is null
     * @throws IOException          if an I/O error occurs
     *
     */
    public static long copyLarge(final InputStream input, final OutputStream output) throws IOException {
        return copy(input, output, DEFAULT_BUFFER_SIZE);
    }

    /**
     * Copies bytes from a large (over 2GB) <code>InputStream</code> to an
     * <code>OutputStream</code>.
     * <p>
     * This method uses the provided buffer, so there is no need to use a
     * <code>BufferedInputStream</code>.
     * <p>
     *
     * @param input  the <code>InputStream</code> to read from
     * @param output the <code>OutputStream</code> to write to
     * @param buffer the buffer to use for the copy
     * @return the number of bytes copied
     * @throws NullPointerException if the input or output is null
     * @throws IOException          if an I/O error occurs
     *
     */
    public static long copyLarge(final InputStream input, final OutputStream output, final byte[] buffer)
            throws IOException {
        var count = 0L;
        int n;
        while (EOF != (n = input.read(buffer))) {
            output.write(buffer, 0, n);
            count += n;
        }
        return count;
    }

    /**
     * Copies some or all bytes from a large (over 2GB) <code>InputStream</code> to
     * an <code>OutputStream</code>, optionally skipping input bytes.
     * <p>
     * This method buffers the input internally, so there is no need to use a
     * <code>BufferedInputStream</code>.
     * </p>
     * <p>
     * Note that the implementation uses {@link #skip(InputStream, long)}. This
     * means that the method may be considerably less efficient than using the
     * actual skip implementation, this is done to guarantee that the correct number
     * of characters are skipped.
     * </p>
     * The buffer size is given by {@link #DEFAULT_BUFFER_SIZE}.
     *
     * @param input       the <code>InputStream</code> to read from
     * @param output      the <code>OutputStream</code> to write to
     * @param inputOffset number of bytes to skip from input before copying -ve
     *                    values are ignored
     * @param length      number of bytes to copy. -ve means all
     * @return the number of bytes copied
     * @throws NullPointerException if the input or output is null
     * @throws IOException          if an I/O error occurs
     *
     */
    public static long copyLarge(final InputStream input, final OutputStream output, final long inputOffset,
            final long length) throws IOException {
        return copyLarge(input, output, inputOffset, length, new byte[DEFAULT_BUFFER_SIZE]);
    }

    /**
     * Copies some or all bytes from a large (over 2GB) <code>InputStream</code> to
     * an <code>OutputStream</code>, optionally skipping input bytes.
     * <p>
     * This method uses the provided buffer, so there is no need to use a
     * <code>BufferedInputStream</code>.
     * </p>
     * <p>
     * Note that the implementation uses {@link #skip(InputStream, long)}. This
     * means that the method may be considerably less efficient than using the
     * actual skip implementation, this is done to guarantee that the correct number
     * of characters are skipped.
     * </p>
     *
     * @param input       the <code>InputStream</code> to read from
     * @param output      the <code>OutputStream</code> to write to
     * @param inputOffset number of bytes to skip from input before copying -ve
     *                    values are ignored
     * @param length      number of bytes to copy. -ve means all
     * @param buffer      the buffer to use for the copy
     * @return the number of bytes copied
     * @throws NullPointerException if the input or output is null
     * @throws IOException          if an I/O error occurs
     *
     */
    public static long copyLarge(final InputStream input, final OutputStream output, final long inputOffset,
            final long length, final byte[] buffer) throws IOException {
        if (inputOffset > 0) {
            skipFully(input, inputOffset);
        }
        if (length == 0) {
            return 0;
        }
        final var bufferLength = buffer.length;
        var bytesToRead = bufferLength;
        if (length > 0 && length < bufferLength) {
            bytesToRead = (int) length;
        }
        int read;
        var totalRead = 0L;
        while (bytesToRead > 0 && EOF != (read = input.read(buffer, 0, bytesToRead))) {
            output.write(buffer, 0, read);
            totalRead += read;
            if (length > 0) { // only adjust length if not reading to the end
                // Note the cast must work because buffer.length is an integer
                bytesToRead = (int) Math.min(length - totalRead, bufferLength);
            }
        }
        return totalRead;
    }

    /**
     * Copies bytes from an <code>InputStream</code> to chars on a
     * <code>Writer</code> using the specified character encoding.
     * <p>
     * This method buffers the input internally, so there is no need to use a
     * <code>BufferedInputStream</code>.
     * <p>
     * This method uses {@link InputStreamReader}.
     *
     * @param input         the <code>InputStream</code> to read from
     * @param output        the <code>Writer</code> to write to
     * @param inputEncoding the encoding to use for the input stream, null means
     *                      platform default
     * @throws NullPointerException if the input or output is null
     * @throws IOException          if an I/O error occurs
     *
     */
    public static void copy(final InputStream input, final Writer output, final Charset inputEncoding)
            throws IOException {
        final var in = new InputStreamReader(input, toCharset(inputEncoding));
        copy(in, output);
    }

    /**
     * Returns the given Charset or the default Charset if the given Charset is
     * null.
     *
     * @param charset A charset or null.
     * @return the given Charset or the default Charset if the given Charset is null
     */
    public static Charset toCharset(final Charset charset) {
        return charset == null ? Charset.defaultCharset() : charset;
    }

    /**
     * Copies bytes from an <code>InputStream</code> to chars on a
     * <code>Writer</code> using the specified character encoding.
     * <p>
     * This method buffers the input internally, so there is no need to use a
     * <code>BufferedInputStream</code>.
     * <p>
     * Character encoding names can be found at
     * <a href="http://www.iana.org/assignments/character-sets">IANA</a>.
     * <p>
     * This method uses {@link InputStreamReader}.
     *
     * @param input         the <code>InputStream</code> to read from
     * @param output        the <code>Writer</code> to write to
     * @param inputEncoding the encoding to use for the InputStream, null means
     *                      platform default
     * @throws NullPointerException                         if the input or output
     *                                                      is null
     * @throws IOException                                  if an I/O error occurs
     * @throws java.nio.charset.UnsupportedCharsetException thrown instead of
     *                                                      {@link java.io
     *                                                      .UnsupportedEncodingException}
     *                                                      in version 2.2 if the
     *                                                      encoding is not
     *                                                      supported.
     *
     */
    public static void copy(final InputStream input, final Writer output, final String inputEncoding)
            throws IOException {
        copy(input, output, toCharset(inputEncoding));
    }

    /**
     * Returns a Charset for the named charset. If the name is null, return the
     * default Charset.
     *
     * @param charset The name of the requested charset, may be null.
     * @return a Charset for the named charset
     * @throws java.nio.charset.UnsupportedCharsetException If the named charset is
     *                                                      unavailable
     */
    public static Charset toCharset(final String charset) {
        return charset == null ? Charset.defaultCharset() : Charset.forName(charset);
    }

    // copy from Reader
    // -----------------------------------------------------------------------

    /**
     * Copies chars from a <code>Reader</code> to a <code>Writer</code>.
     * <p>
     * This method buffers the input internally, so there is no need to use a
     * <code>BufferedReader</code>.
     * <p>
     * Large streams (over 2GB) will return a chars copied value of <code>-1</code>
     * after the copy has completed since the correct number of chars cannot be
     * returned as an int. For large streams use the
     * <code>copyLarge(Reader, Writer)</code> method.
     *
     * @param input  the <code>Reader</code> to read from
     * @param output the <code>Writer</code> to write to
     * @return the number of characters copied, or -1 if &gt; Integer.MAX_VALUE
     * @throws NullPointerException if the input or output is null
     * @throws IOException          if an I/O error occurs
     *
     */
    public static int copy(final Reader input, final Writer output) throws IOException {
        final var count = copyLarge(input, output);
        if (count > Integer.MAX_VALUE) {
            return -1;
        }
        return (int) count;
    }

    /**
     * Copies chars from a large (over 2GB) <code>Reader</code> to a
     * <code>Writer</code>.
     * <p>
     * This method buffers the input internally, so there is no need to use a
     * <code>BufferedReader</code>.
     * <p>
     * The buffer size is given by {@link #DEFAULT_BUFFER_SIZE}.
     *
     * @param input  the <code>Reader</code> to read from
     * @param output the <code>Writer</code> to write to
     * @return the number of characters copied
     * @throws NullPointerException if the input or output is null
     * @throws IOException          if an I/O error occurs
     *
     */
    public static long copyLarge(final Reader input, final Writer output) throws IOException {
        return copyLarge(input, output, new char[DEFAULT_BUFFER_SIZE]);
    }

    /**
     * Copies chars from a large (over 2GB) <code>Reader</code> to a
     * <code>Writer</code>.
     * <p>
     * This method uses the provided buffer, so there is no need to use a
     * <code>BufferedReader</code>.
     * <p>
     *
     * @param input  the <code>Reader</code> to read from
     * @param output the <code>Writer</code> to write to
     * @param buffer the buffer to be used for the copy
     * @return the number of characters copied
     * @throws NullPointerException if the input or output is null
     * @throws IOException          if an I/O error occurs
     *
     */
    public static long copyLarge(final Reader input, final Writer output, final char[] buffer) throws IOException {
        var count = 0L;
        int n;
        while (EOF != (n = input.read(buffer))) {
            output.write(buffer, 0, n);
            count += n;
        }
        return count;
    }

    /**
     * Copies some or all chars from a large (over 2GB) <code>InputStream</code> to
     * an <code>OutputStream</code>, optionally skipping input chars.
     * <p>
     * This method buffers the input internally, so there is no need to use a
     * <code>BufferedReader</code>.
     * <p>
     * The buffer size is given by {@link #DEFAULT_BUFFER_SIZE}.
     *
     * @param input       the <code>Reader</code> to read from
     * @param output      the <code>Writer</code> to write to
     * @param inputOffset number of chars to skip from input before copying -ve
     *                    values are ignored
     * @param length      number of chars to copy. -ve means all
     * @return the number of chars copied
     * @throws NullPointerException if the input or output is null
     * @throws IOException          if an I/O error occurs
     *
     */
    public static long copyLarge(final Reader input, final Writer output, final long inputOffset, final long length)
            throws IOException {
        return copyLarge(input, output, inputOffset, length, new char[DEFAULT_BUFFER_SIZE]);
    }

    /**
     * Copies some or all chars from a large (over 2GB) <code>InputStream</code> to
     * an <code>OutputStream</code>, optionally skipping input chars.
     * <p>
     * This method uses the provided buffer, so there is no need to use a
     * <code>BufferedReader</code>.
     * <p>
     *
     * @param input       the <code>Reader</code> to read from
     * @param output      the <code>Writer</code> to write to
     * @param inputOffset number of chars to skip from input before copying -ve
     *                    values are ignored
     * @param length      number of chars to copy. -ve means all
     * @param buffer      the buffer to be used for the copy
     * @return the number of chars copied
     * @throws NullPointerException if the input or output is null
     * @throws IOException          if an I/O error occurs
     *
     */
    public static long copyLarge(final Reader input, final Writer output, final long inputOffset, final long length,
            final char[] buffer) throws IOException {
        if (inputOffset > 0) {
            skipFully(input, inputOffset);
        }
        if (length == 0) {
            return 0;
        }
        var bytesToRead = buffer.length;
        if (length > 0 && length < buffer.length) {
            bytesToRead = (int) length;
        }
        int read;
        var totalRead = 0L;
        while (bytesToRead > 0 && EOF != (read = input.read(buffer, 0, bytesToRead))) {
            output.write(buffer, 0, read);
            totalRead += read;
            if (length > 0) { // only adjust length if not reading to the end
                // Note the cast must work because buffer.length is an integer
                bytesToRead = (int) Math.min(length - totalRead, buffer.length);
            }
        }
        return totalRead;
    }

    /**
     * Copies chars from a <code>Reader</code> to bytes on an
     * <code>OutputStream</code> using the specified character encoding, and calling
     * flush.
     * <p>
     * This method buffers the input internally, so there is no need to use a
     * <code>BufferedReader</code>.
     * </p>
     * <p>
     * Due to the implementation of OutputStreamWriter, this method performs a
     * flush.
     * </p>
     * <p>
     * This method uses {@link OutputStreamWriter}.
     * </p>
     *
     * @param input          the <code>Reader</code> to read from
     * @param output         the <code>OutputStream</code> to write to
     * @param outputEncoding the encoding to use for the OutputStream, null means
     *                       platform default
     * @throws NullPointerException if the input or output is null
     * @throws IOException          if an I/O error occurs
     *
     */
    public static void copy(final Reader input, final OutputStream output, final Charset outputEncoding)
            throws IOException {
        final var out = new OutputStreamWriter(output, toCharset(outputEncoding));
        copy(input, out);
        // Unless anyone is planning on rewriting OutputStreamWriter,
        // we have to flush here.
        out.flush();
    }

    /**
     * Copies chars from a <code>Reader</code> to bytes on an
     * <code>OutputStream</code> using the specified character encoding, and calling
     * flush.
     * <p>
     * This method buffers the input internally, so there is no need to use a
     * <code>BufferedReader</code>.
     * <p>
     * Character encoding names can be found at
     * <a href="http://www.iana.org/assignments/character-sets">IANA</a>.
     * <p>
     * Due to the implementation of OutputStreamWriter, this method performs a
     * flush.
     * <p>
     * This method uses {@link OutputStreamWriter}.
     *
     * @param input          the <code>Reader</code> to read from
     * @param output         the <code>OutputStream</code> to write to
     * @param outputEncoding the encoding to use for the OutputStream, null means
     *                       platform default
     * @throws NullPointerException                         if the input or output
     *                                                      is null
     * @throws IOException                                  if an I/O error occurs
     * @throws java.nio.charset.UnsupportedCharsetException thrown instead of
     *                                                      {@link java.io
     *                                                      .UnsupportedEncodingException}
     *                                                      in version 2.2 if the
     *                                                      encoding is not
     *                                                      supported.
     *
     */
    public static void copy(final Reader input, final OutputStream output, final String outputEncoding)
            throws IOException {
        copy(input, output, toCharset(outputEncoding));
    }

    /**
     * Skips bytes from an input byte stream. This implementation guarantees that it
     * will read as many bytes as possible before giving up; this may not always be
     * the case for skip() implementations in subclasses of {@link InputStream}.
     * <p>
     * Note that the implementation uses {@link InputStream#read(byte[], int, int)}
     * rather than delegating to {@link InputStream#skip(long)}. This means that the
     * method may be considerably less efficient than using the actual skip
     * implementation, this is done to guarantee that the correct number of bytes
     * are skipped.
     * </p>
     *
     * @param input  byte stream to skip
     * @param toSkip number of bytes to skip.
     * @return number of bytes actually skipped.
     * @throws IOException              if there is a problem reading the file
     * @throws IllegalArgumentException if toSkip is negative
     * @see InputStream#skip(long)
     * @see <a href="https://issues.apache.org/jira/browse/IO-203">IO-203 - Add
     *      skipFully() method for InputStreams</a>
     *
     */
    public static long skip(final InputStream input, final long toSkip) throws IOException {
        if (toSkip < 0) {
            throw new IllegalArgumentException(SKIP_COUNT_MUST_BE_NON_NEGATIVE_ACTUAL + toSkip);
        }
        /*
         * N.B. no need to synchronize this because: - we don't care if the buffer is
         * created multiple times (the data is ignored) - we always use the same size
         * buffer, so if it is recreated it will still be OK (if the buffer size were
         * variable, we would need to synch. to ensure some other thread did not create
         * a smaller one)
         */
        if (skipByteBuffer == null) {
            skipByteBuffer = new byte[SKIP_BUFFER_SIZE];
        }
        var remain = toSkip;
        while (remain > 0) {
            // See https://issues.apache.org/jira/browse/IO-203 for why we use read() rather
            // than
            // delegating to skip()
            final long n = input.read(skipByteBuffer, 0, (int) Math.min(remain, SKIP_BUFFER_SIZE));
            if (n < 0) { // EOF
                break;
            }
            remain -= n;
        }
        return toSkip - remain;
    }

    /**
     * Skips characters from an input character stream. This implementation
     * guarantees that it will read as many characters as possible before giving up;
     * this may not always be the case for skip() implementations in subclasses of
     * {@link Reader}.
     * <p>
     * Note that the implementation uses {@link Reader#read(char[], int, int)}
     * rather than delegating to {@link Reader#skip(long)}. This means that the
     * method may be considerably less efficient than using the actual skip
     * implementation, this is done to guarantee that the correct number of
     * characters are skipped.
     * </p>
     *
     * @param input  character stream to skip
     * @param toSkip number of characters to skip.
     * @return number of characters actually skipped.
     * @throws IOException              if there is a problem reading the file
     * @throws IllegalArgumentException if toSkip is negative
     * @see Reader#skip(long)
     * @see <a href="https://issues.apache.org/jira/browse/IO-203">IO-203 - Add
     *      skipFully() method for InputStreams</a>
     *
     */
    public static long skip(final Reader input, final long toSkip) throws IOException {
        if (toSkip < 0) {
            throw new IllegalArgumentException(SKIP_COUNT_MUST_BE_NON_NEGATIVE_ACTUAL + toSkip);
        }
        /*
         * N.B. no need to synchronize this because: - we don't care if the buffer is
         * created multiple times (the data is ignored) - we always use the same size
         * buffer, so if it is recreated it will still be OK (if the buffer size were
         * variable, we would need to sync. to ensure some other thread did not create a
         * smaller one)
         */
        if (skipCharBuffer == null) {
            skipCharBuffer = new char[SKIP_BUFFER_SIZE];
        }
        var remain = toSkip;
        while (remain > 0) {
            // See https://issues.apache.org/jira/browse/IO-203 for why we use read() rather
            // than
            // delegating to skip()
            final long n = input.read(skipCharBuffer, 0, (int) Math.min(remain, SKIP_BUFFER_SIZE));
            if (n < 0) { // EOF
                break;
            }
            remain -= n;
        }
        return toSkip - remain;
    }

    /**
     * Skips the requested number of bytes or fail if there are not enough left.
     * <p>
     * This allows for the possibility that {@link InputStream#skip(long)} may not
     * skip as many bytes as requested (most likely because of reaching EOF).
     * <p>
     * Note that the implementation uses {@link #skip(InputStream, long)}. This
     * means that the method may be considerably less efficient than using the
     * actual skip implementation, this is done to guarantee that the correct number
     * of characters are skipped.
     * </p>
     *
     * @param input  stream to skip
     * @param toSkip the number of bytes to skip
     * @throws IOException              if there is a problem reading the file
     * @throws IllegalArgumentException if toSkip is negative
     * @throws EOFException             if the number of bytes skipped was incorrect
     * @see InputStream#skip(long)
     *
     */
    public static void skipFully(final InputStream input, final long toSkip) throws IOException {
        if (toSkip < 0) {
            throw new IllegalArgumentException("Bytes to skip must not be negative: " + toSkip);
        }
        final var skipped = skip(input, toSkip);
        if (skipped != toSkip) {
            throw new EOFException("Bytes to skip: " + toSkip + ACTUAL + skipped);
        }
    }

    /**
     * Skips the requested number of characters or fail if there are not enough
     * left.
     * <p>
     * This allows for the possibility that {@link Reader#skip(long)} may not skip
     * as many characters as requested (most likely because of reaching EOF).
     * <p>
     * Note that the implementation uses {@link #skip(Reader, long)}. This means
     * that the method may be considerably less efficient than using the actual skip
     * implementation, this is done to guarantee that the correct number of
     * characters are skipped.
     * </p>
     *
     * @param input  stream to skip
     * @param toSkip the number of characters to skip
     * @throws IOException              if there is a problem reading the file
     * @throws IllegalArgumentException if toSkip is negative
     * @throws EOFException             if the number of characters skipped was
     *                                  incorrect
     * @see Reader#skip(long)
     *
     */
    public static void skipFully(final Reader input, final long toSkip) throws IOException {
        final var skipped = skip(input, toSkip);
        if (skipped != toSkip) {
            throw new EOFException("Chars to skip: " + toSkip + ACTUAL + skipped);
        }
    }

    // InputStream to byte array

    /**
     * Gets the contents of an <code>InputStream</code> as a <code>byte[]</code>.
     * <p>
     * This method buffers the input internally, so there is no need to use a
     * <code>BufferedInputStream</code>.
     *
     * @param input the <code>InputStream</code> to read from
     * @return the requested byte array
     * @throws NullPointerException if the input is null
     * @throws IOException          if an I/O error occurs
     */
    public static byte[] toByteArray(final InputStream input) throws IOException {
        try (final var output = new ByteArrayOutputStream()) {
            copy(input, output);
            return output.toByteArray();
        }
    }

}
