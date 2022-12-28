package io.cui.tools.codec;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import lombok.Getter;
import lombok.ToString;

/**
 * Converts hexadecimal Strings. The Charset used for certain operation can be set, the default is
 * set in {@link StandardCharsets#UTF_8}
 *
 * This class is thread-safe.
 * <h3>Usage</h3>
 *
 * <pre>
 * String roundtrip = "roundtrip";
 * assertEquals(roundtrip, new String(Hex.decodeHex(Hex.encodeHex(roundtrip.getBytes()))));
 * </pre>
 *
 *
 * @author https://github.com/apache/commons-codec/blob/master/src/main/java/org/apache/commons/codec/binary/Hex.java
 */
@ToString
public class Hex {

    /**
     * Default charset is {@link StandardCharsets#UTF_8}
     */
    public static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;

    /**
     * Used to build output as Hex
     */
    private static final char[] DIGITS_LOWER = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd',
        'e', 'f' };

    /**
     * Used to build output as Hex
     */
    private static final char[] DIGITS_UPPER = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D',
        'E', 'F' };

    /**
     * Converts a String representing hexadecimal values into an array of bytes of those same
     * values. The returned array will be half the length of the passed String, as it takes two
     * characters to represent any given byte. An exception is thrown if the passed String has an
     * odd number of elements.
     *
     * @param data A String containing hexadecimal digits
     * @return A byte array containing binary data decoded from the supplied char array.
     * @throws DecoderException Thrown if an odd number or illegal of characters is supplied
     */
    public static byte[] decodeHex(final String data) throws DecoderException {
        return decodeHex(data.toCharArray());
    }

    /**
     * Converts an array of characters representing hexadecimal values into an array of bytes of
     * those same values. The
     * returned array will be half the length of the passed array, as it takes two characters to
     * represent any given
     * byte. An exception is thrown if the passed char array has an odd number of elements.
     *
     * @param data An array of characters containing hexadecimal digits
     * @return A byte array containing binary data decoded from the supplied char array.
     * @throws DecoderException Thrown if an odd number or illegal of characters is supplied
     */
    @SuppressWarnings("squid:ForLoopCounterChangedCheck") // owolff: original code
    public static byte[] decodeHex(final char[] data) throws DecoderException {

        final int len = data.length;

        if ((len & 0x01) != 0) {
            throw new DecoderException("Odd number of characters.");
        }

        final byte[] out = new byte[len >> 1];

        // two characters form the hex value.
        for (int i = 0, j = 0; j < len; i++) {
            int f = toDigit(data[j], j) << 4;
            j++;
            f = f | toDigit(data[j], j);
            j++;
            out[i] = (byte) (f & 0xFF);
        }

        return out;
    }

    /**
     * Converts an array of bytes into an array of characters representing the hexadecimal values of
     * each byte in order.
     * The returned array will be double the length of the passed array, as it takes two characters
     * to represent any
     * given byte.
     *
     * @param data a byte[] to convert to Hex characters
     * @return A char[] containing lower-case hexadecimal characters
     */
    public static char[] encodeHex(final byte[] data) {
        return encodeHex(data, true);
    }

    /**
     * Converts a byte buffer into an array of characters representing the hexadecimal values of
     * each byte in order. The
     * returned array will be double the length of the passed array, as it takes two characters to
     * represent any given
     * byte.
     *
     * <p>
     * All bytes identified by {@link ByteBuffer#remaining()} will be used; after this method
     * the value {@link ByteBuffer#remaining() remaining()} will be zero.
     * </p>
     *
     * @param data a byte buffer to convert to Hex characters
     * @return A char[] containing lower-case hexadecimal characters
     */
    public static char[] encodeHex(final ByteBuffer data) {
        return encodeHex(data, true);
    }

    /**
     * Converts an array of bytes into an array of characters representing the hexadecimal values of
     * each byte in order.
     * The returned array will be double the length of the passed array, as it takes two characters
     * to represent any
     * given byte.
     *
     * @param data a byte[] to convert to Hex characters
     * @param toLowerCase {@code true} converts to lowercase, {@code false} to uppercase
     * @return A char[] containing hexadecimal characters in the selected case
     *
     */
    public static char[] encodeHex(final byte[] data, final boolean toLowerCase) {
        return encodeHex(data, toLowerCase ? DIGITS_LOWER : DIGITS_UPPER);
    }

    /**
     * Converts a byte buffer into an array of characters representing the hexadecimal values of
     * each byte in order. The
     * returned array will be double the length of the passed array, as it takes two characters to
     * represent any given
     * byte.
     *
     * <p>
     * All bytes identified by {@link ByteBuffer#remaining()} will be used; after this method
     * the value {@link ByteBuffer#remaining() remaining()} will be zero.
     * </p>
     *
     * @param data a byte buffer to convert to Hex characters
     * @param toLowerCase {@code true} converts to lowercase, {@code false} to uppercase
     * @return A char[] containing hexadecimal characters in the selected case
     */
    public static char[] encodeHex(final ByteBuffer data, final boolean toLowerCase) {
        return encodeHex(data, toLowerCase ? DIGITS_LOWER : DIGITS_UPPER);
    }

    /**
     * Converts an array of bytes into an array of characters representing the hexadecimal values of
     * each byte in order.
     * The returned array will be double the length of the passed array, as it takes two characters
     * to represent any
     * given byte.
     *
     * @param data a byte[] to convert to Hex characters
     * @param toDigits the output alphabet (must contain at least 16 chars)
     * @return A char[] containing the appropriate characters from the alphabet For best results,
     *         this should be either
     *         upper- or lower-case hex.
     *
     */
    @SuppressWarnings("squid:ForLoopCounterChangedCheck") // owolff: original code
    protected static char[] encodeHex(final byte[] data, final char[] toDigits) {
        final int l = data.length;
        final char[] out = new char[l << 1];
        // two characters form the hex value.
        for (int i = 0, j = 0; i < l; i++) {
            out[j++] = toDigits[(0xF0 & data[i]) >>> 4];
            out[j++] = toDigits[0x0F & data[i]];
        }
        return out;
    }

    /**
     * Converts a byte buffer into an array of characters representing the hexadecimal values of
     * each byte in order. The
     * returned array will be double the length of the passed array, as it takes two characters to
     * represent any given
     * byte.
     *
     * <p>
     * All bytes identified by {@link ByteBuffer#remaining()} will be used; after this method
     * the value {@link ByteBuffer#remaining() remaining()} will be zero.
     * </p>
     *
     * @param byteBuffer a byte buffer to convert to Hex characters
     * @param toDigits the output alphabet (must be at least 16 characters)
     * @return A char[] containing the appropriate characters from the alphabet For best results,
     *         this should be either
     *         upper- or lower-case hex.
     *
     */
    protected static char[] encodeHex(final ByteBuffer byteBuffer, final char[] toDigits) {
        return encodeHex(toByteArray(byteBuffer), toDigits);
    }

    /**
     * Converts an array of bytes into a String representing the hexadecimal values of each byte in
     * order. The returned
     * String will be double the length of the passed array, as it takes two characters to represent
     * any given byte.
     *
     * @param data a byte[] to convert to Hex characters
     * @return A String containing lower-case hexadecimal characters
     *
     */
    public static String encodeHexString(final byte[] data) {
        return new String(encodeHex(data));
    }

    /**
     * Converts an array of bytes into a String representing the hexadecimal values of each byte in
     * order. The returned
     * String will be double the length of the passed array, as it takes two characters to represent
     * any given byte.
     *
     * @param data a byte[] to convert to Hex characters
     * @param toLowerCase {@code true} converts to lowercase, {@code false} to uppercase
     * @return A String containing lower-case hexadecimal characters
     *
     */
    public static String encodeHexString(final byte[] data, final boolean toLowerCase) {
        return new String(encodeHex(data, toLowerCase));
    }

    /**
     * Converts a byte buffer into a String representing the hexadecimal values of each byte in
     * order. The returned
     * String will be double the length of the passed array, as it takes two characters to represent
     * any given byte.
     *
     * <p>
     * All bytes identified by {@link ByteBuffer#remaining()} will be used; after this method
     * the value {@link ByteBuffer#remaining() remaining()} will be zero.
     * </p>
     *
     * @param data a byte buffer to convert to Hex characters
     * @return A String containing lower-case hexadecimal characters
     *
     */
    public static String encodeHexString(final ByteBuffer data) {
        return new String(encodeHex(data));
    }

    /**
     * Converts a byte buffer into a String representing the hexadecimal values of each byte in
     * order. The returned
     * String will be double the length of the passed array, as it takes two characters to represent
     * any given byte.
     *
     * <p>
     * All bytes identified by {@link ByteBuffer#remaining()} will be used; after this method
     * the value {@link ByteBuffer#remaining() remaining()} will be zero.
     * </p>
     *
     * @param data a byte buffer to convert to Hex characters
     * @param toLowerCase {@code true} converts to lowercase, {@code false} to uppercase
     * @return A String containing lower-case hexadecimal characters
     *
     */
    public static String encodeHexString(final ByteBuffer data, final boolean toLowerCase) {
        return new String(encodeHex(data, toLowerCase));
    }

    /**
     * Convert the byte buffer to a byte array. All bytes identified by
     * {@link ByteBuffer#remaining()} will be used.
     *
     * @param byteBuffer the byte buffer
     * @return the byte[]
     */
    private static byte[] toByteArray(final ByteBuffer byteBuffer) {
        final int remaining = byteBuffer.remaining();
        // Use the underlying buffer if possible
        if (byteBuffer.hasArray()) {
            final byte[] byteArray = byteBuffer.array();
            if (remaining == byteArray.length) {
                byteBuffer.position(remaining);
                return byteArray;
            }
        }
        // Copy the bytes
        final byte[] byteArray = new byte[remaining];
        byteBuffer.get(byteArray);
        return byteArray;
    }

    /**
     * Converts a hexadecimal character to an integer.
     *
     * @param ch A character to convert to an integer digit
     * @param index The index of the character in the source
     * @return An integer
     * @throws DecoderException Thrown if ch is an illegal hex character
     */
    protected static int toDigit(final char ch, final int index) throws DecoderException {
        final int digit = Character.digit(ch, 16);
        if (digit == -1) {
            throw new DecoderException("Illegal hexadecimal character " + ch + " at index " + index);
        }
        return digit;
    }

    @Getter
    private final Charset charset;

    /**
     * Creates a new codec with the default charset name {@link #DEFAULT_CHARSET}
     */
    public Hex() {
        // use default encoding
        charset = DEFAULT_CHARSET;
    }

    /**
     * Creates a new codec with the given Charset.
     *
     * @param charset the charset.
     *
     */
    public Hex(final Charset charset) {
        this.charset = charset;
    }

    /**
     * Creates a new codec with the given charset name.
     *
     * @param charsetName the charset name.
     * @throws java.nio.charset.UnsupportedCharsetException If the named charset is unavailable
     *
     *             throws UnsupportedCharsetException if the named charset is unavailable
     */
    public Hex(final String charsetName) {
        this(Charset.forName(charsetName));
    }

    /**
     * Converts an array of character bytes representing hexadecimal values into an array of bytes
     * of those same values.
     * The returned array will be half the length of the passed array, as it takes two characters to
     * represent any given
     * byte. An exception is thrown if the passed char array has an odd number of elements.
     *
     * @param array An array of character bytes containing hexadecimal digits
     * @return A byte array containing binary data decoded from the supplied byte array
     *         (representing characters).
     * @throws DecoderException Thrown if an odd number of characters is supplied to this function
     * @see #decodeHex(char[])
     */
    public byte[] decode(final byte[] array) throws DecoderException {
        return decodeHex(new String(array, getCharset()).toCharArray());
    }

    /**
     * Converts a buffer of character bytes representing hexadecimal values into an array of bytes
     * of those same values.
     * The returned array will be half the length of the passed array, as it takes two characters to
     * represent any given
     * byte. An exception is thrown if the passed char array has an odd number of elements.
     *
     * <p>
     * All bytes identified by {@link ByteBuffer#remaining()} will be used; after this method
     * the value {@link ByteBuffer#remaining() remaining()} will be zero.
     * </p>
     *
     * @param buffer An array of character bytes containing hexadecimal digits
     * @return A byte array containing binary data decoded from the supplied byte array
     *         (representing characters).
     * @throws DecoderException Thrown if an odd number of characters is supplied to this function
     * @see #decodeHex(char[])
     *
     */
    public byte[] decode(final ByteBuffer buffer) throws DecoderException {
        return decodeHex(new String(toByteArray(buffer), getCharset()).toCharArray());
    }

    /**
     * Converts a String or an array of character bytes representing hexadecimal values into an
     * array of bytes of those
     * same values. The returned array will be half the length of the passed String or array, as it
     * takes two characters
     * to represent any given byte. An exception is thrown if the passed char array has an odd
     * number of elements.
     *
     * @param object A String, ByteBuffer, byte[], or an array of character bytes containing
     *            hexadecimal digits
     * @return A byte array containing binary data decoded from the supplied byte array
     *         (representing characters).
     * @throws DecoderException Thrown if an odd number of characters is supplied to this function
     *             or the object is not
     *             a String or char[]
     * @see #decodeHex(char[])
     */
    public Object decode(final Object object) throws DecoderException {
        if (object instanceof String) {
            return decode(((String) object).toCharArray());
        } else if (object instanceof byte[]) {
            return decode((byte[]) object);
        } else if (object instanceof ByteBuffer) {
            return decode((ByteBuffer) object);
        } else {
            try {
                return decodeHex((char[]) object);
            } catch (final ClassCastException e) {
                throw new DecoderException(e.getMessage(), e);
            }
        }
    }

    /**
     * Converts an array of bytes into an array of bytes for the characters representing the
     * hexadecimal values of each
     * byte in order. The returned array will be double the length of the passed array, as it takes
     * two characters to
     * represent any given byte.
     * <p>
     * The conversion from hexadecimal characters to the returned bytes is performed with the
     * charset named by {@link #getCharset()}.
     * </p>
     *
     * @param array a byte[] to convert to Hex characters
     * @return A byte[] containing the bytes of the lower-case hexadecimal characters
     *         No longer throws IllegalStateException if the charsetName is invalid.
     * @see #encodeHex(byte[])
     */
    public byte[] encode(final byte[] array) {
        return encodeHexString(array).getBytes(getCharset());
    }

    /**
     * Converts byte buffer into an array of bytes for the characters representing the hexadecimal
     * values of each byte
     * in order. The returned array will be double the length of the passed array, as it takes two
     * characters to
     * represent any given byte.
     *
     * <p>
     * The conversion from hexadecimal characters to the returned bytes is performed with the
     * charset named by
     * {@link #getCharset()}.
     * </p>
     *
     * <p>
     * All bytes identified by {@link ByteBuffer#remaining()} will be used; after this method
     * the value {@link ByteBuffer#remaining() remaining()} will be zero.
     * </p>
     *
     * @param array a byte buffer to convert to Hex characters
     * @return A byte[] containing the bytes of the lower-case hexadecimal characters
     * @see #encodeHex(byte[])
     */
    public byte[] encode(final ByteBuffer array) {
        return encodeHexString(array).getBytes(getCharset());
    }

    /**
     * Converts a String or an array of bytes into an array of characters representing the
     * hexadecimal values of each
     * byte in order. The returned array will be double the length of the passed String or array, as
     * it takes two
     * characters to represent any given byte.
     * <p>
     * The conversion from hexadecimal characters to bytes to be encoded to performed with the
     * charset named by {@link #getCharset()}.
     * </p>
     *
     * @param object a String, ByteBuffer, or byte[] to convert to Hex characters
     * @return A char[] containing lower-case hexadecimal characters
     * @throws EncoderException Thrown if the given object is not a String or byte[]
     * @see #encodeHex(byte[])
     */
    public Object encode(final Object object) throws EncoderException {
        byte[] byteArray;
        if (object instanceof String) {
            byteArray = ((String) object).getBytes(getCharset());
        } else if (object instanceof ByteBuffer) {
            byteArray = toByteArray((ByteBuffer) object);
        } else {
            try {
                byteArray = (byte[]) object;
            } catch (final ClassCastException e) {
                throw new EncoderException(e.getMessage(), e);
            }
        }
        return encodeHex(byteArray);
    }

}
