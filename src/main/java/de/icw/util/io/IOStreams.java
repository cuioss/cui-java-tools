package de.icw.util.io;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;

import lombok.experimental.UtilityClass;

/**
 * Provides a number of utilities in context {@link InputStream} and {@link OutputStream}s. The
 * content is inspired / copied from org.apache.commons.io.IOUtils
 *
 * @author Oliver Wolff
 *
 */
@UtilityClass
public class IOStreams {

    /**
     * Represents the end-of-file (or stream).
     */
    public static final int EOF = -1;

    /**
     * Compares the contents of two Streams to determine if they are equal or
     * not.
     * <p>
     * This method buffers the input internally using
     * <code>BufferedInputStream</code> if they are not already buffered.
     *
     * @param input1 the first stream
     * @param input2 the second stream
     * @return true if the content of the streams are equal or they both don't
     *         exist, false otherwise
     * @throws NullPointerException if either input is null
     * @throws IOException if an I/O error occurs
     */
    public static boolean contentEquals(InputStream input1, InputStream input2)
        throws IOException {
        if (input1 == input2) {
            return true;
        }
        if (!(input1 instanceof BufferedInputStream)) {
            input1 = new BufferedInputStream(input1);
        }
        if (!(input2 instanceof BufferedInputStream)) {
            input2 = new BufferedInputStream(input2);
        }

        int ch = input1.read();
        while (EOF != ch) {
            final int ch2 = input2.read();
            if (ch != ch2) {
                return false;
            }
            ch = input1.read();
        }

        final int ch2 = input2.read();
        return ch2 == EOF;
    }

    /**
     * Compares the contents of two Readers to determine if they are equal or
     * not.
     * <p>
     * This method buffers the input internally using
     * <code>BufferedReader</code> if they are not already buffered.
     *
     * @param input1 the first reader
     * @param input2 the second reader
     * @return true if the content of the readers are equal or they both don't
     *         exist, false otherwise
     * @throws NullPointerException if either input is null
     * @throws IOException if an I/O error occurs
     */
    @SuppressWarnings("resource") // owolff: assuming resource is handled correctly from the caller
    public static boolean contentEquals(Reader input1, Reader input2)
        throws IOException {
        if (input1 == input2) {
            return true;
        }

        input1 = toBufferedReader(input1);
        input2 = toBufferedReader(input2);

        int ch = input1.read();
        while (EOF != ch) {
            final int ch2 = input2.read();
            if (ch != ch2) {
                return false;
            }
            ch = input1.read();
        }

        final int ch2 = input2.read();
        return ch2 == EOF;
    }

    /**
     * Returns the given reader if it is a {@link BufferedReader}, otherwise creates a
     * BufferedReader from the given reader.
     *
     * @param reader the reader to wrap or return (not null)
     * @return the given reader or a new {@link BufferedReader} for the given reader
     * @throws NullPointerException if the input parameter is null
     */
    public static BufferedReader toBufferedReader(final Reader reader) {
        return reader instanceof BufferedReader ? (BufferedReader) reader : new BufferedReader(reader);
    }
}
