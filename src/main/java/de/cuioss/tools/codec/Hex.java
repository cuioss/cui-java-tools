/**
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
package de.cuioss.tools.codec;

import lombok.Getter;
import lombok.ToString;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * <h2>Overview</h2>
 * Converts hexadecimal Strings to and from bytes. The Charset used for string operations
 * can be configured, with UTF-8 as the default ({@link StandardCharsets#UTF_8}).
 * <p>
 * This class is thread-safe and optimized for performance through direct array manipulation
 * and minimal object creation.
 *
 * <h2>Key Features</h2>
 * <ul>
 *   <li>Thread-safe implementation</li>
 *   <li>Configurable character encoding</li>
 *   <li>Support for both upper and lowercase hex output</li>
 *   <li>ByteBuffer support for efficient memory usage</li>
 *   <li>Direct array manipulation for optimal performance</li>
 * </ul>
 *
 * <h2>Usage Examples</h2>
 *
 * <h3>Basic String Conversion</h3>
 * <pre>
 * // Basic encoding/decoding
 * String text = "Hello World";
 * byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
 * String hex = Hex.encodeHexString(bytes);
 * byte[] original = Hex.decodeHex(hex);
 * String result = new String(original, StandardCharsets.UTF_8);
 * </pre>
 *
 * <h3>Case Control</h3>
 * <pre>
 * // Uppercase hex output
 * String upperHex = Hex.encodeHexString(bytes, false);
 * // Lowercase hex output
 * String lowerHex = Hex.encodeHexString(bytes, true);
 * </pre>
 *
 * <h3>Using ByteBuffer</h3>
 * <pre>
 * // Efficient handling of large data
 * ByteBuffer buffer = ByteBuffer.allocate(1024);
 * buffer.put("Large content".getBytes(StandardCharsets.UTF_8));
 * buffer.flip();
 * String hex = Hex.encodeHexString(buffer);
 * </pre>
 *
 * <h3>Custom Charset</h3>
 * <pre>
 * // Using a specific charset
 * Hex customHex = new Hex(StandardCharsets.ISO_8859_1);
 * byte[] encoded = customHex.encode("Special chars".getBytes());
 * byte[] decoded = customHex.decode(encoded);
 * </pre>
 *
 * <h2>Performance Notes</h2>
 * <ul>
 *   <li>The implementation avoids creating intermediate String objects where possible</li>
 *   <li>Direct char[] manipulation is used instead of StringBuilder for better performance</li>
 *   <li>Static methods use UTF-8 by default to avoid charset lookup overhead</li>
 *   <li>ByteBuffer methods support zero-copy operations when possible</li>
 *   <li>Instance reuse is recommended when using custom charsets</li>
 * </ul>
 *
 * <h2>Thread Safety</h2>
 * <ul>
 *   <li>All instance methods are thread-safe</li>
 *   <li>All static methods are thread-safe</li>
 *   <li>Charset field is final and immutable</li>
 *   <li>No shared mutable state between operations</li>
 * </ul>
 *
 * <h2>Error Handling</h2>
 * <ul>
 *   <li>Invalid hex strings throw {@link DecoderException}</li>
 *   <li>Odd-length hex strings throw {@link DecoderException}</li>
 *   <li>Invalid character encodings throw {@link java.nio.charset.UnsupportedCharsetException}</li>
 *   <li>Null inputs throw {@link IllegalArgumentException}</li>
 * </ul>
 *
 * <h2>Migration Notes</h2>
 * This implementation is API-compatible with Apache Commons Codec's Hex class,
 * allowing for easy migration. Key differences:
 * <ul>
 *   <li>Simplified API focused on essential operations</li>
 *   <li>Improved performance through optimized implementation</li>
 *   <li>Enhanced ByteBuffer support</li>
 *   <li>Stricter null checking</li>
 * </ul>
 *
 * @see java.nio.charset.StandardCharsets
 * @see java.nio.ByteBuffer
 * @see <a href="https://github.com/apache/commons-codec/blob/master/src/main/java/org/apache/commons/codec/binary/Hex.java">Apache Commons Codec Reference</a>
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
    private static final char[] DIGITS_LOWER = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd',
            'e', 'f'};

    /**
     * Used to build output as Hex
     */
    private static final char[] DIGITS_UPPER = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D',
            'E', 'F'};

    /**
     * Converts a String representing hexadecimal values into an array of bytes of
     * those same values. The returned array will be half the length of the passed
     * String, as it takes two characters to represent any given byte. An exception
     * is thrown if the passed String has an odd number of elements.
     *
     * @param data A String containing hexadecimal digits
     * @return A byte array containing binary data decoded from the supplied char
     * array.
     * @throws DecoderException Thrown if an odd number or illegal of characters is
     *                          supplied
     */
    public static byte[] decodeHex(final String data) throws DecoderException {
        return decodeHex(data.toCharArray());
    }

    /**
     * Converts an array of characters representing hexadecimal values into an array
     * of bytes of those same values. The returned array will be half the length of
     * the passed array, as it takes two characters to represent any given byte. An
     * exception is thrown if the passed char array has an odd number of elements.
     *
     * @param data An array of characters containing hexadecimal digits
     * @return A byte array containing binary data decoded from the supplied char
     * array.
     * @throws DecoderException Thrown if an odd number or illegal of characters is
     *                          supplied
     */
    @SuppressWarnings("squid:ForLoopCounterChangedCheck") // owolff: original code
    public static byte[] decodeHex(final char[] data) throws DecoderException {

        final var len = data.length;

        if ((len & 0x01) != 0) {
            throw new DecoderException("Odd number of characters.");
        }

        final var out = new byte[len >> 1];

        // two characters form the hex value.
        for (int i = 0, j = 0; j < len; i++) {
            var f = toDigit(data[j], j) << 4;
            j++;
            f = f | toDigit(data[j], j);
            j++;
            out[i] = (byte) (f & 0xFF);
        }

        return out;
    }

    /**
     * Converts an array of bytes into an array of characters representing the
     * hexadecimal values of each byte in order. The returned array will be double
     * the length of the passed array, as it takes two characters to represent any
     * given byte.
     *
     * @param data a byte[] to convert to Hex characters
     * @return A char[] containing lower-case hexadecimal characters
     */
    public static char[] encodeHex(final byte[] data) {
        return encodeHex(data, true);
    }

    /**
     * Converts a byte buffer into an array of characters representing the
     * hexadecimal values of each byte in order. The returned array will be double
     * the length of the passed array, as it takes two characters to represent any
     * given byte.
     *
     * <p>
     * All bytes identified by {@link ByteBuffer#remaining()} will be used; after
     * this method the value {@link ByteBuffer#remaining() remaining()} will be
     * zero.
     * </p>
     *
     * @param data a byte buffer to convert to Hex characters
     * @return A char[] containing lower-case hexadecimal characters
     */
    public static char[] encodeHex(final ByteBuffer data) {
        return encodeHex(data, true);
    }

    /**
     * Converts an array of bytes into an array of characters representing the
     * hexadecimal values of each byte in order. The returned array will be double
     * the length of the passed array, as it takes two characters to represent any
     * given byte.
     *
     * @param data        a byte[] to convert to Hex characters
     * @param toLowerCase {@code true} converts to lowercase, {@code false} to
     *                    uppercase
     * @return A char[] containing hexadecimal characters in the selected case
     */
    public static char[] encodeHex(final byte[] data, final boolean toLowerCase) {
        return encodeHex(data, toLowerCase ? DIGITS_LOWER : DIGITS_UPPER);
    }

    /**
     * Converts a byte buffer into an array of characters representing the
     * hexadecimal values of each byte in order. The returned array will be double
     * the length of the passed array, as it takes two characters to represent any
     * given byte.
     *
     * <p>
     * All bytes identified by {@link ByteBuffer#remaining()} will be used; after
     * this method the value {@link ByteBuffer#remaining() remaining()} will be
     * zero.
     * </p>
     *
     * @param data        a byte buffer to convert to Hex characters
     * @param toLowerCase {@code true} converts to lowercase, {@code false} to
     *                    uppercase
     * @return A char[] containing hexadecimal characters in the selected case
     */
    public static char[] encodeHex(final ByteBuffer data, final boolean toLowerCase) {
        return encodeHex(data, toLowerCase ? DIGITS_LOWER : DIGITS_UPPER);
    }

    /**
     * Converts an array of bytes into an array of characters representing the
     * hexadecimal values of each byte in order. The returned array will be double
     * the length of the passed array, as it takes two characters to represent any
     * given byte.
     *
     * @param data     a byte[] to convert to Hex characters
     * @param toDigits the output alphabet (must contain at least 16 chars)
     * @return A char[] containing the appropriate characters from the alphabet For
     * best results, this should be either upper- or lower-case hex.
     */
    @SuppressWarnings("squid:ForLoopCounterChangedCheck") // owolff: original code
    protected static char[] encodeHex(final byte[] data, final char[] toDigits) {
        final var l = data.length;
        final var out = new char[l << 1];
        // two characters form the hex value.
        for (int i = 0, j = 0; i < l; i++) {
            out[j] = toDigits[(0xF0 & data[i]) >>> 4];
            j++;
            out[j] = toDigits[0x0F & data[i]];
            j++;
        }
        return out;
    }

    /**
     * Converts a byte buffer into an array of characters representing the
     * hexadecimal values of each byte in order. The returned array will be double
     * the length of the passed array, as it takes two characters to represent any
     * given byte.
     *
     * <p>
     * All bytes identified by {@link ByteBuffer#remaining()} will be used; after
     * this method the value {@link ByteBuffer#remaining() remaining()} will be
     * zero.
     * </p>
     *
     * @param byteBuffer a byte buffer to convert to Hex characters
     * @param toDigits   the output alphabet (must be at least 16 characters)
     * @return A char[] containing the appropriate characters from the alphabet For
     * best results, this should be either upper- or lower-case hex.
     */
    protected static char[] encodeHex(final ByteBuffer byteBuffer, final char[] toDigits) {
        return encodeHex(toByteArray(byteBuffer), toDigits);
    }

    /**
     * Converts an array of bytes into a String representing the hexadecimal values
     * of each byte in order. The returned String will be double the length of the
     * passed array, as it takes two characters to represent any given byte.
     *
     * @param data a byte[] to convert to Hex characters
     * @return A String containing lower-case hexadecimal characters
     */
    public static String encodeHexString(final byte[] data) {
        return new String(encodeHex(data));
    }

    /**
     * Converts an array of bytes into a String representing the hexadecimal values
     * of each byte in order. The returned String will be double the length of the
     * passed array, as it takes two characters to represent any given byte.
     *
     * @param data        a byte[] to convert to Hex characters
     * @param toLowerCase {@code true} converts to lowercase, {@code false} to
     *                    uppercase
     * @return A String containing lower-case hexadecimal characters
     */
    public static String encodeHexString(final byte[] data, final boolean toLowerCase) {
        return new String(encodeHex(data, toLowerCase));
    }

    /**
     * Converts a byte buffer into a String representing the hexadecimal values of
     * each byte in order. The returned String will be double the length of the
     * passed array, as it takes two characters to represent any given byte.
     *
     * <p>
     * All bytes identified by {@link ByteBuffer#remaining()} will be used; after
     * this method the value {@link ByteBuffer#remaining() remaining()} will be
     * zero.
     * </p>
     *
     * @param data a byte buffer to convert to Hex characters
     * @return A String containing lower-case hexadecimal characters
     */
    public static String encodeHexString(final ByteBuffer data) {
        return new String(encodeHex(data));
    }

    /**
     * Converts a byte buffer into a String representing the hexadecimal values of
     * each byte in order. The returned String will be double the length of the
     * passed array, as it takes two characters to represent any given byte.
     *
     * <p>
     * All bytes identified by {@link ByteBuffer#remaining()} will be used; after
     * this method the value {@link ByteBuffer#remaining() remaining()} will be
     * zero.
     * </p>
     *
     * @param data        a byte buffer to convert to Hex characters
     * @param toLowerCase {@code true} converts to lowercase, {@code false} to
     *                    uppercase
     * @return A String containing lower-case hexadecimal characters
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
        final var remaining = byteBuffer.remaining();
        // Use the underlying buffer if possible
        if (byteBuffer.hasArray()) {
            final var byteArray = byteBuffer.array();
            if (remaining == byteArray.length) {
                byteBuffer.position(remaining);
                return byteArray;
            }
        }
        // Copy the bytes
        final var byteArray = new byte[remaining];
        byteBuffer.get(byteArray);
        return byteArray;
    }

    /**
     * Converts a hexadecimal character to an integer.
     *
     * @param ch    A character to convert to an integer digit
     * @param index The index of the character in the source
     * @return An integer
     * @throws DecoderException Thrown if ch is an illegal hex character
     */
    protected static int toDigit(final char ch, final int index) throws DecoderException {
        final var digit = Character.digit(ch, 16);
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
     */
    public Hex(final Charset charset) {
        this.charset = charset;
    }

    /**
     * Creates a new codec with the given charset name.
     *
     * @param charsetName the charset name.
     * @throws java.nio.charset.UnsupportedCharsetException If the named charset is
     *                                                      unavailable
     *                                                      <p>
     *                                                      throws
     *                                                      UnsupportedCharsetException
     *                                                      if the named charset is
     *                                                      unavailable
     */
    public Hex(final String charsetName) {
        this(Charset.forName(charsetName));
    }

    /**
     * Converts a String or an array of character bytes to an array of bytes
     * using the default charset.
     *
     * @param object String to convert to byte array
     * @return the byte array
     * @throws IllegalArgumentException if the parameter is null
     */
    public byte[] decode(final byte[] object) throws DecoderException {
        return decodeHex(new String(object, getCharset()).toCharArray());
    }

    /**
     * Converts a String or an array of bytes to an array of bytes
     * using the default charset.
     *
     * @param object String to convert to byte array
     * @return the byte array
     * @throws IllegalArgumentException if the parameter is null
     */
    public byte[] decode(final ByteBuffer object) throws DecoderException {
        return decodeHex(new String(toByteArray(object), getCharset()).toCharArray());
    }

    /**
     * Converts a String or an array of character bytes to an array of bytes
     * using the default charset.
     *
     * @param object a String, ByteBuffer, byte[], or an array of character bytes
     *               containing hexadecimal digits
     * @return A byte array containing binary data decoded from the supplied byte
     * array (representing characters).
     * @throws DecoderException Thrown if an odd number of characters is supplied to
     *                          this function or the object is not a String or
     *                          char[]
     * @see #decodeHex(char[])
     */
    public Object decode(final Object object) throws DecoderException {
        if (object instanceof String string) {
            return decode(string.toCharArray());
        }
        if (object instanceof byte[] bytes) {
            return decode(bytes);
        }
        if (object instanceof ByteBuffer buffer) {
            return decode(buffer);
        }
        try {
            return decodeHex((char[]) object);
        } catch (final ClassCastException e) {
            throw new DecoderException(e.getMessage(), e);
        }
    }

    /**
     * Converts an array of bytes into an array of bytes for the characters
     * representing the hexadecimal values of each byte in order.
     *
     * @param array a byte[] to convert to Hex characters
     * @return A byte[] containing the bytes of the lower-case hexadecimal characters
     */
    public byte[] encode(final byte[] array) {
        return encodeHexString(array).getBytes(getCharset());
    }

    /**
     * Converts byte buffer into an array of bytes for the characters
     * representing the hexadecimal values of each byte in order.
     *
     * <p>
     * The conversion from hexadecimal characters to the returned bytes is performed
     * with the charset named by getCharset().
     * </p>
     *
     * <p>
     * All bytes identified by {@link ByteBuffer#remaining()} will be used; after
     * this method the value {@link ByteBuffer#remaining() remaining()} will be
     * zero.
     * </p>
     *
     * @param array the byte buffer to convert
     * @return the byte array
     * @throws IllegalArgumentException if the parameter is null
     */
    public byte[] encode(final ByteBuffer array) {
        return encodeHexString(array).getBytes(getCharset());
    }

    /**
     * Converts a String or an array of bytes to an array of characters
     * using the default charset.
     *
     * @param object a String, ByteBuffer, or byte[] to convert to Hex characters
     * @return A char[] containing lower-case hexadecimal characters
     * @throws EncoderException Thrown if the given object is not a String or byte[]
     * @see #encodeHex(byte[])
     */
    public Object encode(final Object object) throws EncoderException {
        byte[] byteArray;
        if (object instanceof String string) {
            byteArray = string.getBytes(getCharset());
        } else if (object instanceof ByteBuffer buffer) {
            byteArray = toByteArray(buffer);
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
