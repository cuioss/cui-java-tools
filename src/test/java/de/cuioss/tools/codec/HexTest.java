/*
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

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
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

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link Hex} class, based on Apache Commons Codec's HexTest.
 */
@DisplayName("Hex should")
@EnableGeneratorController
class HexTest {

    private static final String BAD_ENCODING_NAME = "UNKNOWN";

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
        void customCharset() {
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
        void customCharsetBadName() {
            assertThrows(UnsupportedCharsetException.class, () -> new Hex(BAD_ENCODING_NAME));
        }
    }

    @Nested
    @DisplayName("handle decoding operations")
    class DecodingOperations {

        @Test
        @DisplayName("throw exception for bad character at position 0")
        void decodeBadCharacterPos0() {
            assertThrows(DecoderException.class, () -> new Hex().decode("q0"));
        }

        @Test
        @DisplayName("throw exception for bad character at position 1")
        void decodeBadCharacterPos1() {
            assertThrows(DecoderException.class, () -> new Hex().decode("0q"));
        }

        @Test
        @DisplayName("handle empty byte array")
        void decodeByteArrayEmpty() throws DecoderException {
            assertArrayEquals(new byte[0], new Hex().decode(new byte[0]));
        }

        @Test
        @DisplayName("handle empty byte buffer")
        void decodeByteBufferEmpty() throws DecoderException {
            assertArrayEquals(new byte[0], new Hex().decode(ByteBuffer.allocate(0)));
        }

        @Test
        @DisplayName("throw exception for odd number of characters")
        void decodeByteArrayOddCharacters() {
            assertThrows(DecoderException.class, () -> new Hex().decode(new byte[]{65}));
            assertThrows(DecoderException.class, () -> new Hex().decode(ByteBuffer.wrap(new byte[]{65})));
            assertThrows(DecoderException.class, () -> new Hex().decode("ABC"));
        }

        @Test
        @DisplayName("throw exception for invalid class type")
        void decodeClassCastException() {
            assertThrows(DecoderException.class, () -> new Hex().decode(new int[]{65}));
        }
    }

    @Nested
    @DisplayName("handle encoding operations")
    class EncodingOperations {

        @Test
        @DisplayName("handle empty byte array")
        void encodeByteArrayEmpty() {
            assertArrayEquals(new byte[0], new Hex().encode(new byte[0]));
        }

        @Test
        @DisplayName("handle empty byte buffer")
        void encodeByteBufferEmpty() {
            assertArrayEquals(new byte[0], new Hex().encode(ByteBuffer.allocate(0)));
        }

        @Test
        @DisplayName("throw exception for invalid class type")
        void encodeClassCastException() {
            assertThrows(EncoderException.class, () -> new Hex().encode(new int[]{65}));
        }

        @ParameterizedTest(name = "encode '{0}' correctly")
        @ValueSource(strings = {"Hello World", "The quick brown fox jumps over the lazy dog"})
        void encodeString(String input) {
            final var hex = new Hex();
            final var expected = new String(hex.encode(input.getBytes(StandardCharsets.UTF_8)));
            assertEquals(expected, Hex.encodeHexString(input.getBytes(StandardCharsets.UTF_8)));
        }

        @Test
        @DisplayName("handle read-only byte buffer")
        void encodeReadOnlyByteBuffer() {
            final var bb = ByteBuffer.allocate(16);
            final var expected = Hex.encodeHexString(bb.array());
            bb.asReadOnlyBuffer();
            assertEquals(expected, Hex.encodeHexString(bb));
        }
    }

    @Nested
    @DisplayName("handle static method operations")
    class StaticMethodOperations {

        @Test
        @DisplayName("decode hex string correctly")
        void decodeHexString() throws DecoderException {
            final var input = "48656c6c6f20576f726c64";
            final var expected = "Hello World".getBytes(StandardCharsets.UTF_8);
            assertArrayEquals(expected, Hex.decodeHex(input));
        }

        @Test
        @DisplayName("decode hex char array correctly")
        void decodeHexCharArray() throws DecoderException {
            final var input = "48656c6c6f20576f726c64".toCharArray();
            final var expected = "Hello World".getBytes(StandardCharsets.UTF_8);
            assertArrayEquals(expected, Hex.decodeHex(input));
        }

        @Test
        @DisplayName("throw exception for odd length hex string")
        void decodeHexOddLength() {
            assertThrows(DecoderException.class, () -> Hex.decodeHex("ABC"));
            assertThrows(DecoderException.class, () -> Hex.decodeHex("ABC".toCharArray()));
        }

        @Test
        @DisplayName("throw exception for invalid hex characters")
        void decodeHexInvalidCharacters() {
            assertThrows(DecoderException.class, () -> Hex.decodeHex("XY"));
            assertThrows(DecoderException.class, () -> Hex.decodeHex("XY".toCharArray()));
        }

        @Test
        @DisplayName("encode byte array to hex chars")
        void encodeHexByteArray() {
            final var input = "Hello World".getBytes(StandardCharsets.UTF_8);
            final var result = Hex.encodeHex(input);
            final var expected = "48656c6c6f20576f726c64".toCharArray();
            assertArrayEquals(expected, result);
        }

        @Test
        @DisplayName("encode byte buffer to hex chars")
        void encodeHexByteBuffer() {
            final var input = "Hello World".getBytes(StandardCharsets.UTF_8);
            final var buffer = ByteBuffer.wrap(input);
            final var result = Hex.encodeHex(buffer);
            final var expected = "48656c6c6f20576f726c64".toCharArray();
            assertArrayEquals(expected, result);
        }

        @Test
        @DisplayName("encode byte array with case control")
        void encodeHexByteArrayWithCase() {
            final var input = new byte[]{(byte) 0xAB, (byte) 0xCD, (byte) 0xEF};

            final var lowerResult = Hex.encodeHex(input, true);
            assertArrayEquals("abcdef".toCharArray(), lowerResult);

            final var upperResult = Hex.encodeHex(input, false);
            assertArrayEquals("ABCDEF".toCharArray(), upperResult);
        }

        @Test
        @DisplayName("encode byte buffer with case control")
        void encodeHexByteBufferWithCase() {
            final var input = new byte[]{(byte) 0xAB, (byte) 0xCD, (byte) 0xEF};
            final var buffer = ByteBuffer.wrap(input);

            final var lowerResult = Hex.encodeHex(buffer, true);
            assertArrayEquals("abcdef".toCharArray(), lowerResult);

            buffer.rewind();
            final var upperResult = Hex.encodeHex(buffer, false);
            assertArrayEquals("ABCDEF".toCharArray(), upperResult);
        }

        @Test
        @DisplayName("encode hex string from byte array")
        void encodeHexStringByteArray() {
            final var input = "Hello World".getBytes(StandardCharsets.UTF_8);
            final var result = Hex.encodeHexString(input);
            assertEquals("48656c6c6f20576f726c64", result);
        }

        @Test
        @DisplayName("encode hex string from byte array with case control")
        void encodeHexStringByteArrayWithCase() {
            final var input = new byte[]{(byte) 0xAB, (byte) 0xCD, (byte) 0xEF};

            final var lowerResult = Hex.encodeHexString(input, true);
            assertEquals("abcdef", lowerResult);

            final var upperResult = Hex.encodeHexString(input, false);
            assertEquals("ABCDEF", upperResult);
        }

        @Test
        @DisplayName("encode hex string from byte buffer")
        void encodeHexStringByteBuffer() {
            final var input = "Hello World".getBytes(StandardCharsets.UTF_8);
            final var buffer = ByteBuffer.wrap(input);
            final var result = Hex.encodeHexString(buffer);
            assertEquals("48656c6c6f20576f726c64", result);
        }

        @Test
        @DisplayName("encode hex string from byte buffer with case control")
        void encodeHexStringByteBufferWithCase() {
            final var input = new byte[]{(byte) 0xAB, (byte) 0xCD, (byte) 0xEF};
            final var buffer = ByteBuffer.wrap(input);

            final var lowerResult = Hex.encodeHexString(buffer, true);
            assertEquals("abcdef", lowerResult);

            buffer.rewind();
            final var upperResult = Hex.encodeHexString(buffer, false);
            assertEquals("ABCDEF", upperResult);
        }

        @Test
        @DisplayName("handle empty inputs")
        void handleEmptyInputs() throws DecoderException {
            // Empty string decode
            assertArrayEquals(new byte[0], Hex.decodeHex(""));
            assertArrayEquals(new byte[0], Hex.decodeHex(new char[0]));

            // Empty byte array encode
            assertArrayEquals(new char[0], Hex.encodeHex(new byte[0]));
            assertEquals("", Hex.encodeHexString(new byte[0]));

            // Empty byte buffer encode
            final var emptyBuffer = ByteBuffer.allocate(0);
            assertArrayEquals(new char[0], Hex.encodeHex(emptyBuffer));

            emptyBuffer.rewind();
            assertEquals("", Hex.encodeHexString(emptyBuffer));
        }
    }

    @Nested
    @DisplayName("handle constructor operations")
    class ConstructorOperations {

        @Test
        @DisplayName("create with default constructor")
        void defaultConstructor() {
            final var hex = new Hex();
            assertEquals(StandardCharsets.UTF_8, hex.getCharset());
        }

        @Test
        @DisplayName("verify toString method")
        void toStringMethod() {
            final var hex = new Hex();
            final var result = hex.toString();
            // Just verify it doesn't throw and contains class name
            assertTrue(result.contains("Hex"));
        }
    }

    @Nested
    @DisplayName("handle round trip operations")
    class RoundTripOperations {

        @Test
        @DisplayName("correctly encode and decode random data")
        void roundTripRandom() throws DecoderException {
            final var hex = new Hex();

            for (int i = 0; i < 100; i++) {
                final var size = Generators.integers(0, 256).next();
                final var bytes = new byte[size];
                new Random().nextBytes(bytes);

                final var encoded = hex.encode(bytes);
                final var decoded = hex.decode(encoded);

                assertArrayEquals(bytes, decoded);
            }
        }

        @Test
        @DisplayName("correctly handle case sensitivity")
        void roundTripCaseSensitivity() throws DecoderException {
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
