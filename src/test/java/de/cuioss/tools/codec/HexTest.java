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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.charset.UnsupportedCharsetException;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Tests for {@link Hex} class, based on Apache Commons Codec's HexTest.
 */
@DisplayName("Hex should")
class HexTest {

    private static final String BAD_ENCODING_NAME = "UNKNOWN";

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

    private boolean charsetSanityCheck(final String name) {
        final var source = "the quick brown dog jumped over the lazy fox";
        try {
            final var bytes = source.getBytes(name);
            final var str = new String(bytes, name);
            return source.equals(str);
        } catch (Exception e) {
            return false;
        }
    }

    @Nested
    @DisplayName("handle charset operations")
    class CharsetOperations {

        @Test
        @DisplayName("use custom charset")
        void testCustomCharset() {
            final var customCharsetNames = new String[]{"UTF-8", "UTF-16", "UTF-16BE", "UTF-16LE",
                    "US-ASCII", "ISO-8859-1"};

            for (String name : customCharsetNames) {
                if (charsetSanityCheck(name)) {
                    final var charset = Charset.forName(name);
                    assertEquals(charset, new Hex(charset).getCharset());
                    assertEquals(charset, new Hex(name).getCharset());
                }
            }
        }

        @Test
        @DisplayName("throw exception for invalid charset name")
        void testCustomCharsetBadName() {
            assertThrows(UnsupportedCharsetException.class, () -> new Hex(BAD_ENCODING_NAME));
        }
    }

    @Nested
    @DisplayName("handle decoding operations")
    class DecodingOperations {

        @Test
        @DisplayName("throw exception for bad character at position 0")
        void testDecodeBadCharacterPos0() {
            assertThrows(DecoderException.class, () -> new Hex().decode("q0"));
        }

        @Test
        @DisplayName("throw exception for bad character at position 1")
        void testDecodeBadCharacterPos1() {
            assertThrows(DecoderException.class, () -> new Hex().decode("0q"));
        }

        @Test
        @DisplayName("handle empty byte array")
        void testDecodeByteArrayEmpty() throws DecoderException {
            assertArrayEquals(new byte[0], new Hex().decode(new byte[0]));
        }

        @Test
        @DisplayName("handle empty byte buffer")
        void testDecodeByteBufferEmpty() throws DecoderException {
            assertArrayEquals(new byte[0], new Hex().decode(ByteBuffer.allocate(0)));
        }

        @Test
        @DisplayName("throw exception for odd number of characters")
        void testDecodeByteArrayOddCharacters() {
            assertThrows(DecoderException.class, () -> new Hex().decode(new byte[]{65}));
            assertThrows(DecoderException.class, () -> new Hex().decode(ByteBuffer.wrap(new byte[]{65})));
            assertThrows(DecoderException.class, () -> new Hex().decode("ABC"));
        }

        @Test
        @DisplayName("throw exception for invalid class type")
        void testDecodeClassCastException() {
            assertThrows(DecoderException.class, () -> new Hex().decode(new int[]{65}));
        }
    }

    @Nested
    @DisplayName("handle encoding operations")
    class EncodingOperations {

        @Test
        @DisplayName("handle empty byte array")
        void testEncodeByteArrayEmpty() {
            assertArrayEquals(new byte[0], new Hex().encode(new byte[0]));
        }

        @Test
        @DisplayName("handle empty byte buffer")
        void testEncodeByteBufferEmpty() {
            assertArrayEquals(new byte[0], new Hex().encode(ByteBuffer.allocate(0)));
        }

        @Test
        @DisplayName("throw exception for invalid class type")
        void testEncodeClassCastException() {
            assertThrows(EncoderException.class, () -> new Hex().encode(new int[]{65}));
        }

        @ParameterizedTest(name = "encode '{0}' correctly")
        @ValueSource(strings = {"Hello World", "The quick brown fox jumps over the lazy dog"})
        void testEncodeString(String input) {
            final var hex = new Hex();
            final var expected = new String(hex.encode(input.getBytes(StandardCharsets.UTF_8)));
            assertEquals(expected, Hex.encodeHexString(input.getBytes(StandardCharsets.UTF_8)));
        }

        @Test
        @DisplayName("handle read-only byte buffer")
        void testEncodeReadOnlyByteBuffer() {
            final var bb = ByteBuffer.allocate(16);
            final var expected = Hex.encodeHexString(bb.array());
            bb.asReadOnlyBuffer();
            assertEquals(expected, Hex.encodeHexString(bb));
        }
    }

    @Nested
    @DisplayName("handle round trip operations")
    class RoundTripOperations {

        @Test
        @DisplayName("correctly encode and decode random data")
        void testRoundTripRandom() throws DecoderException {
            final var hex = new Hex();
            final var random = new Random();

            for (int i = 0; i < 100; i++) {
                final var bytes = new byte[random.nextInt(256)];
                random.nextBytes(bytes);

                final var encoded = hex.encode(bytes);
                final var decoded = hex.decode(encoded);

                assertArrayEquals(bytes, decoded);
            }
        }

        @Test
        @DisplayName("correctly handle case sensitivity")
        void testRoundTripCaseSensitivity() throws DecoderException {
            final var hex = new Hex();
            final var data = "Hello World".getBytes(StandardCharsets.UTF_8);

            final var encoded = Hex.encodeHexString(data);
            final var upperCase = encoded.toUpperCase();
            final var lowerCase = encoded.toLowerCase();

            assertArrayEquals(data, (byte[]) hex.decode(upperCase));
            assertArrayEquals(data, (byte[]) hex.decode(lowerCase));
        }
    }
}
