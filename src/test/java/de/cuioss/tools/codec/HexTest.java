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
package de.cuioss.tools.codec;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.Test;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.charset.UnsupportedCharsetException;
import java.util.Arrays;
import java.util.Random;

/**
 * @author <a href="https://github.com/apache/commons-codec/blob/master/src/test/java/org/apache/commons/codec/binary/HexTest.java">...</a>
 *
 */
@SuppressWarnings("java:S5785")
// owolff: I will not change because I want to stay ins sync with
// original test-case
class HexTest {

    private static final String BAD_ENCODING_NAME = "UNKNOWN";

    private final static boolean LOG = false;

    /**
     * Allocate a ByteBuffer.
     *
     * <p>
     * The default implementation uses {@link ByteBuffer#allocate(int)}. The method
     * is overridden in AllocateDirectHexTest to use
     * {@link ByteBuffer#allocateDirect(int)}
     *
     * @param capacity the capacity
     * @return the byte buffer
     */
    protected ByteBuffer allocate(final int capacity) {
        return ByteBuffer.allocate(capacity);
    }

    /**
     * Encodes the given string into a byte buffer using the UTF-8 charset.
     *
     * <p>
     * The buffer is allocated using {@link #allocate(int)}.
     *
     * @param string the String to encode
     * @return the byte buffer
     */
    private ByteBuffer getByteBufferUtf8(final String string) {
        final var bytes = string.getBytes(StandardCharsets.UTF_8);
        final var bb = allocate(bytes.length);
        bb.put(bytes);
        bb.flip();
        return bb;
    }

    private boolean charsetSanityCheck(final String name) {
        final var source = "the quick brown dog jumped over the lazy fox";
        try {
            final var bytes = source.getBytes(name);
            final var str = new String(bytes, name);
            final var equals = source.equals(str);
            if (!equals) {
                // Here with:
                //
                // Java Sun 1.4.2_19 x86 32-bits on Windows XP
                // JIS_X0212-1990
                // x-JIS0208
                //
                // Java Sun 1.5.0_17 x86 32-bits on Windows XP
                // JIS_X0212-1990
                // x-IBM834
                // x-JIS0208
                // x-MacDingbat
                // x-MacSymbol
                //
                // Java Sun 1.6.0_14 x86 32-bits
                // JIS_X0212-1990
                // x-IBM834
                // x-JIS0208
                // x-MacDingbat
                // x-MacSymbol
                //
                log("FAILED charsetSanityCheck=Interesting Java charset oddity: Roundtrip failed for " + name);
            }
            return equals;
        } catch (final UnsupportedEncodingException | UnsupportedOperationException e) {
            // Caught here with:
            // x-JISAutoDetect on Windows XP and Java Sun 1.4.2_19 x86 32-bits
            // x-JISAutoDetect on Windows XP and Java Sun 1.5.0_17 x86 32-bits
            // x-JISAutoDetect on Windows XP and Java Sun 1.6.0_14 x86 32-bits
            if (LOG) {
                log("FAILED charsetSanityCheck=" + name + ", e=" + e);
                log(e);
            }
            return false;
        }
    }

    private void checkDecodeHexCharArrayOddCharacters(final char[] data) {
        try {
            Hex.decodeHex(data);
            fail("An exception wasn't thrown when trying to decode an odd number of characters");
        } catch (final DecoderException e) {
            // Expected exception
        }
    }

    private void checkDecodeHexByteBufferOddCharacters(final ByteBuffer data) {
        try {
            new Hex().decode(data);
            fail("An exception wasn't thrown when trying to decode an odd number of characters");
        } catch (final DecoderException e) {
            // Expected exception
        }
    }

    private void checkDecodeHexCharArrayOddCharacters(final String data) {
        try {
            Hex.decodeHex(data);
            fail("An exception wasn't thrown when trying to decode an odd number of characters");
        } catch (final DecoderException e) {
            // Expected exception
        }
    }

    private void log(final String s) {
        if (LOG) {
            System.out.println(s);
            System.out.flush();
        }
    }

    private void log(final Throwable t) {
        if (LOG) {
            t.printStackTrace(System.out);
            System.out.flush();
        }
    }

    @Test
    void testCustomCharset() throws UnsupportedEncodingException, DecoderException {
        for (final String name : Charset.availableCharsets().keySet()) {
            testCustomCharset(name, "testCustomCharset");
        }
    }

    private void testCustomCharset(final String name, final String parent)
            throws UnsupportedEncodingException, DecoderException {
        if (!charsetSanityCheck(name)) {
            return;
        }
        log(parent + "=" + name);
        final var customCodec = new Hex(name);
        // source data
        final var sourceString = "Hello World";
        final var sourceBytes = sourceString.getBytes(name);
        // test 1
        // encode source to hex string to bytes with charset
        final var actualEncodedBytes = customCodec.encode(sourceBytes);
        // encode source to hex string...
        var expectedHexString = Hex.encodeHexString(sourceBytes);
        // ... and get the bytes in the expected charset
        final var expectedHexStringBytes = expectedHexString.getBytes(name);
        assertArrayEquals(expectedHexStringBytes, actualEncodedBytes);
        // test 2
        var actualStringFromBytes = new String(actualEncodedBytes, name);
        assertEquals(expectedHexString, actualStringFromBytes,
                name + ", expectedHexString=" + expectedHexString + ", actualStringFromBytes=" + actualStringFromBytes);
        // second test:
        final var utf8Codec = new Hex();
        expectedHexString = "48656c6c6f20576f726c64";
        final var decodedUtf8Bytes = (byte[]) utf8Codec.decode(expectedHexString);
        actualStringFromBytes = new String(decodedUtf8Bytes, utf8Codec.getCharset());
        // sanity check:
        assertEquals(sourceString, actualStringFromBytes, name);
        // actual check:
        final var decodedCustomBytes = customCodec.decode(actualEncodedBytes);
        actualStringFromBytes = new String(decodedCustomBytes, name);
        assertEquals(sourceString, actualStringFromBytes, name);
    }

    @Test
    void testCustomCharsetBadName() {
        assertThrows(UnsupportedCharsetException.class, () -> {
            new Hex(BAD_ENCODING_NAME);
        });
    }

    @Test
    void testDecodeBadCharacterPos0() {
        try {
            new Hex().decode("q0");
            fail("An exception wasn't thrown when trying to decode an illegal character");
        } catch (final DecoderException e) {
            // Expected exception
        }
    }

    @Test
    void testDecodeBadCharacterPos1() {
        try {
            new Hex().decode("0q");
            fail("An exception wasn't thrown when trying to decode an illegal character");
        } catch (final DecoderException e) {
            // Expected exception
        }
    }

    @Test
    void testDecodeByteArrayEmpty() throws DecoderException {
        assertArrayEquals(new byte[0], new Hex().decode(new byte[0]));
    }

    @Test
    void testDecodeByteArrayObjectEmpty() throws DecoderException {
        assertArrayEquals(new byte[0], (byte[]) new Hex().decode((Object) new byte[0]));
    }

    @Test
    void testDecodeByteArrayOddCharacters() {
        try {
            new Hex().decode(new byte[]{65});
            fail("An exception wasn't thrown when trying to decode an odd number of characters");
        } catch (final DecoderException e) {
            // Expected exception
        }
    }

    @Test
    void testDecodeByteBufferEmpty() throws DecoderException {
        assertArrayEquals(new byte[0], new Hex().decode(allocate(0)));
    }

    @Test
    void testDecodeByteBufferAllocatedButEmpty() throws DecoderException {
        final var bb = allocate(10);
        // Effectively set remaining == 0 => empty
        bb.flip();
        assertArrayEquals(new byte[0], new Hex().decode(bb));
        assertEquals(0, bb.remaining());
    }

    @Test
    void testDecodeByteBufferObjectEmpty() throws DecoderException {
        assertArrayEquals(new byte[0], (byte[]) new Hex().decode((Object) allocate(0)));
    }

    @Test
    void testDecodeByteBufferOddCharacters() {
        final var bb = allocate(1);
        bb.put((byte) 65);
        bb.flip();
        checkDecodeHexByteBufferOddCharacters(bb);
    }

    @Test
    void testDecodeByteBufferWithLimitOddCharacters() {
        final var bb = allocate(10);
        bb.put(1, (byte) 65);
        bb.position(1);
        bb.limit(2);
        checkDecodeHexByteBufferOddCharacters(bb);
    }

    @Test
    void testDecodeHexCharArrayEmpty() throws DecoderException {
        assertArrayEquals(new byte[0], Hex.decodeHex(new char[0]));
    }

    @Test
    void testDecodeHexStringEmpty() throws DecoderException {
        assertArrayEquals(new byte[0], Hex.decodeHex(""));
    }

    @Test
    void testDecodeClassCastException() {
        try {
            new Hex().decode(new int[]{65});
            fail("An exception wasn't thrown when trying to decode.");
        } catch (final DecoderException e) {
            // Expected exception
        }
    }

    @Test
    void testDecodeHexCharArrayOddCharacters1() {
        checkDecodeHexCharArrayOddCharacters(new char[]{'A'});
    }

    @Test
    void testDecodeHexStringOddCharacters1() {
        checkDecodeHexCharArrayOddCharacters("A");
    }

    @Test
    void testDecodeHexCharArrayOddCharacters3() {
        checkDecodeHexCharArrayOddCharacters(new char[]{'A', 'B', 'C'});
    }

    @Test
    void testDecodeHexCharArrayOddCharacters5() {
        checkDecodeHexCharArrayOddCharacters(new char[]{'A', 'B', 'C', 'D', 'E'});
    }

    @Test
    void testDecodeHexStringOddCharacters() {
        try {
            new Hex().decode("6");
            fail("An exception wasn't thrown when trying to decode an odd number of characters");
        } catch (final DecoderException e) {
            // Expected exception
        }
    }

    @Test
    void testDecodeStringEmpty() throws DecoderException {
        assertArrayEquals(new byte[0], (byte[]) new Hex().decode(""));
    }

    @Test
    void testDecodeByteBufferWithLimit() throws DecoderException {
        final var bb = getByteBufferUtf8("000102030405060708090a0b0c0d0e0f");
        final byte[] expected = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        // Test pairs of bytes
        for (var i = 0; i < 15; i++) {
            bb.position(i * 2);
            bb.limit(i * 2 + 4);
            assertEquals(new String(Arrays.copyOfRange(expected, i, i + 2)), new String(new Hex().decode(bb)));
            assertEquals(0, bb.remaining());
        }
    }

    @Test
    void testEncodeByteArrayEmpty() {
        assertArrayEquals(new byte[0], new Hex().encode(new byte[0]));
    }

    @Test
    void testEncodeByteArrayObjectEmpty() throws EncoderException {
        assertArrayEquals(new char[0], (char[]) new Hex().encode((Object) new byte[0]));
    }

    @Test
    void testEncodeByteBufferEmpty() {
        assertArrayEquals(new byte[0], new Hex().encode(allocate(0)));
    }

    @Test
    void testEncodeByteBufferAllocatedButEmpty() {
        final var bb = allocate(10);
        // Effectively set remaining == 0 => empty
        bb.flip();
        assertArrayEquals(new byte[0], new Hex().encode(bb));
        assertEquals(0, bb.remaining());
    }

    @Test
    void testEncodeByteBufferObjectEmpty() throws EncoderException {
        assertArrayEquals(new char[0], (char[]) new Hex().encode((Object) allocate(0)));
    }

    @Test
    void testEncodeClassCastException() {
        try {
            new Hex().encode(new int[]{65});
            fail("An exception wasn't thrown when trying to encode.");
        } catch (final EncoderException e) {
            // Expected exception
        }
    }

    @Test
    void testEncodeDecodeHexCharArrayRandom() throws DecoderException, EncoderException {
        final var random = new Random();

        final var hex = new Hex();
        for (var i = 5; i > 0; i--) {
            final var data = new byte[random.nextInt(10000) + 1];
            random.nextBytes(data);

            // static API
            final var encodedChars = Hex.encodeHex(data);
            var decodedBytes = Hex.decodeHex(encodedChars);
            assertArrayEquals(data, decodedBytes);

            // instance API with array parameter
            final var encodedStringBytes = hex.encode(data);
            decodedBytes = hex.decode(encodedStringBytes);
            assertArrayEquals(data, decodedBytes);

            // instance API with char[] (Object) parameter
            var dataString = new String(encodedChars);
            var encodedStringChars = (char[]) hex.encode(dataString);
            decodedBytes = (byte[]) hex.decode(encodedStringChars);
            assertArrayEquals(getBytesUtf8(dataString), decodedBytes);

            // instance API with String (Object) parameter
            dataString = new String(encodedChars);
            encodedStringChars = (char[]) hex.encode(dataString);
            decodedBytes = (byte[]) hex.decode(new String(encodedStringChars));
            assertArrayEquals(getBytesUtf8(dataString), decodedBytes);
        }
    }

    @Test
    void testEncodeHexByteArrayEmpty() {
        assertArrayEquals(new char[0], Hex.encodeHex(new byte[0]));
        assertArrayEquals(new byte[0], new Hex().encode(new byte[0]));
    }

    @Test
    void testEncodeHexByteArrayHelloWorldLowerCaseHex() {
        final var b = getBytesUtf8("Hello World");
        final var expected = "48656c6c6f20576f726c64";
        char[] actual;
        actual = Hex.encodeHex(b);
        assertEquals(expected, new String(actual));
        actual = Hex.encodeHex(b, true);
        assertEquals(expected, new String(actual));
        actual = Hex.encodeHex(b, false);
        assertNotEquals(expected, new String(actual));
    }

    @Test
    void testEncodeHexByteArrayHelloWorldUpperCaseHex() {
        final var b = getBytesUtf8("Hello World");
        final var expected = "48656C6C6F20576F726C64";
        char[] actual;
        actual = Hex.encodeHex(b);
        assertNotEquals(expected, new String(actual));
        actual = Hex.encodeHex(b, true);
        assertNotEquals(expected, new String(actual));
        actual = Hex.encodeHex(b, false);
        assertEquals(expected, new String(actual));
    }

    @Test
    void testEncodeHexByteArrayZeroes() {
        final var c = Hex.encodeHex(new byte[36]);
        assertEquals("000000000000000000000000000000000000000000000000000000000000000000000000", new String(c));
    }

    @Test
    void testEncodeHexByteBufferEmpty() {
        assertArrayEquals(new char[0], Hex.encodeHex(allocate(0)));
        assertArrayEquals(new byte[0], new Hex().encode(allocate(0)));
    }

    @Test
    void testEncodeHexByteBufferHelloWorldLowerCaseHex() {
        final var b = getByteBufferUtf8("Hello World");
        final var expected = "48656c6c6f20576f726c64";
        char[] actual;
        // Default lower-case
        actual = Hex.encodeHex(b);
        assertEquals(expected, new String(actual));
        assertEquals(0, b.remaining());
        // lower-case
        b.flip();
        actual = Hex.encodeHex(b, true);
        assertEquals(expected, new String(actual));
        assertEquals(0, b.remaining());
        // upper-case
        b.flip();
        actual = Hex.encodeHex(b, false);
        assertEquals(expected.toUpperCase(), new String(actual));
        assertEquals(0, b.remaining());
    }

    @Test
    void testEncodeHexByteBufferHelloWorldUpperCaseHex() {
        final var b = getByteBufferUtf8("Hello World");
        final var expected = "48656C6C6F20576F726C64";
        char[] actual;
        // Default lower-case
        actual = Hex.encodeHex(b);
        assertEquals(expected.toLowerCase(), new String(actual));
        assertEquals(0, b.remaining());
        // lower-case
        b.flip();
        actual = Hex.encodeHex(b, true);
        assertEquals(expected.toLowerCase(), new String(actual));
        assertEquals(0, b.remaining());
        // upper-case
        b.flip();
        actual = Hex.encodeHex(b, false);
        assertEquals(expected, new String(actual));
        assertEquals(0, b.remaining());
    }

    @Test
    void testEncodeHex_ByteBufferOfZeroes() {
        final var c = Hex.encodeHex(allocate(36));
        assertEquals("000000000000000000000000000000000000000000000000000000000000000000000000", new String(c));
    }

    @Test
    void testEncodeHex_ByteBufferWithLimit() {
        final var bb = allocate(16);
        for (var i = 0; i < 16; i++) {
            bb.put((byte) i);
        }
        bb.flip();
        final var expected = "000102030405060708090a0b0c0d0e0f";
        // Test pairs of bytes
        for (var i = 0; i < 15; i++) {
            bb.position(i);
            bb.limit(i + 2);
            assertEquals(expected.substring(i * 2, i * 2 + 4), new String(Hex.encodeHex(bb)));
            assertEquals(0, bb.remaining());
        }
    }

    @Test
    void testEncodeHexByteString_ByteBufferOfZeroes() {
        final var c = Hex.encodeHexString(allocate(36));
        assertEquals("000000000000000000000000000000000000000000000000000000000000000000000000", c);
    }

    @Test
    void testEncodeHexByteString_ByteBufferOfZeroesWithLimit() {
        final var bb = allocate(36);
        bb.limit(3);
        assertEquals("000000", Hex.encodeHexString(bb));
        assertEquals(0, bb.remaining());
        bb.position(1);
        bb.limit(3);
        assertEquals("0000", Hex.encodeHexString(bb));
        assertEquals(0, bb.remaining());
    }

    @Test
    void testEncodeHexByteString_ByteArrayOfZeroes() {
        final var c = Hex.encodeHexString(new byte[36]);
        assertEquals("000000000000000000000000000000000000000000000000000000000000000000000000", c);
    }

    @Test
    void testEncodeHexByteString_ByteArrayBoolean_ToLowerCase() {
        assertEquals("0a", Hex.encodeHexString(new byte[]{10}, true));
    }

    @Test
    void testEncodeHexByteString_ByteArrayBoolean_ToUpperCase() {
        assertEquals("0A", Hex.encodeHexString(new byte[]{10}, false));
    }

    @Test
    void testEncodeHexByteString_ByteBufferBoolean_ToLowerCase() {
        final var bb = allocate(1);
        bb.put((byte) 10);
        bb.flip();
        assertEquals("0a", Hex.encodeHexString(bb, true));
    }

    @Test
    void testEncodeHexByteString_ByteBufferBoolean_ToUpperCase() {
        final var bb = allocate(1);
        bb.put((byte) 10);
        bb.flip();
        assertEquals("0A", Hex.encodeHexString(bb, false));
    }

    @Test
    void testEncodeHexByteString_ByteBufferWithLimitBoolean_ToLowerCase() {
        final var bb = allocate(4);
        bb.put(1, (byte) 10);
        bb.position(1);
        bb.limit(2);
        assertEquals("0a", Hex.encodeHexString(bb, true));
        assertEquals(0, bb.remaining());
    }

    @Test
    void testEncodeHexByteString_ByteBufferWithLimitBoolean_ToUpperCase() {
        final var bb = allocate(4);
        bb.put(1, (byte) 10);
        bb.position(1);
        bb.limit(2);
        assertEquals("0A", Hex.encodeHexString(bb, false));
        assertEquals(0, bb.remaining());
    }

    /**
     * Test encoding of a read only byte buffer. See CODEC-261.
     */
    @Test
    void testEncodeHexReadOnlyByteBuffer() {
        final var chars = Hex.encodeHex(ByteBuffer.wrap(new byte[]{10}).asReadOnlyBuffer());
        assertEquals("0a", String.valueOf(chars));
    }

    @Test
    void testEncodeStringEmpty() throws EncoderException {
        assertArrayEquals(new char[0], (char[]) new Hex().encode(""));
    }

    @Test
    void testGetCharset() {
        assertEquals(StandardCharsets.UTF_8, new Hex(StandardCharsets.UTF_8).getCharset());
    }

    @Test
    void testRequiredCharset() throws UnsupportedEncodingException, DecoderException {
        testCustomCharset("UTF-8", "testRequiredCharset");
        testCustomCharset("UTF-16", "testRequiredCharset");
        testCustomCharset("UTF-16BE", "testRequiredCharset");
        testCustomCharset("UTF-16LE", "testRequiredCharset");
        testCustomCharset("US-ASCII", "testRequiredCharset");
        testCustomCharset("ISO8859_1", "testRequiredCharset");
    }

    @Test
    void shouldRoundTrip() throws Exception {
        var roundtrip = "roundtrip";
        assertEquals(roundtrip, new String(Hex.decodeHex(Hex.encodeHex(roundtrip.getBytes()))));
    }

    static byte[] getBytesUtf8(final String string) {
        if (string == null) {
            return null;
        }
        return string.getBytes(StandardCharsets.UTF_8);
    }
}
