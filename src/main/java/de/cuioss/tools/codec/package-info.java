/**
 * Provides encoding and decoding utilities for various data formats.
 *
 * <h2>Overview</h2>
 * <p>
 * This package offers lightweight encoding and decoding capabilities, inspired by
 * Apache Commons Codec but focused on essential functionality.
 * The implementation prioritizes performance and minimal dependencies.
 * </p>
 *
 * <h2>Key Features</h2>
 * <ul>
 *   <li><b>Hex Encoding/Decoding</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.codec.Hex} - Core class for hex operations</li>
 *       <li>Efficient conversion between bytes and hex strings</li>
 *       <li>Support for both uppercase and lowercase hex output</li>
 *       <li>Thread-safe implementation</li>
 *       <li>ByteBuffer support for improved performance</li>
 *     </ul>
 *   </li>
 *   <li><b>Exception Handling</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.codec.EncoderException} - For encoding errors</li>
 *       <li>{@link de.cuioss.tools.codec.DecoderException} - For decoding errors</li>
 *       <li>Detailed error messages for debugging</li>
 *       <li>Support for cause chaining</li>
 *     </ul>
 *   </li>
 * </ul>
 *
 * <h2>Usage Examples</h2>
 * <h3>Basic Hex Encoding/Decoding</h3>
 * <pre>
 * // Encoding bytes to hex string (uppercase)
 * byte[] bytes = "Hello, World!".getBytes(StandardCharsets.UTF_8);
 * String hexString = Hex.encodeToString(bytes, true);
 * // Result: "48656C6C6F2C20576F726C6421"
 *
 * // Decoding hex string back to bytes
 * try {
 *     byte[] decoded = Hex.decode(hexString);
 *     String original = new String(decoded, StandardCharsets.UTF_8);
 *     // Result: "Hello, World!"
 * } catch (DecoderException e) {
 *     LOGGER.error(e, "Invalid hex string");
 * }
 * </pre>
 *
 * <h3>Using ByteBuffer for Better Performance</h3>
 * <pre>
 * // Encoding from ByteBuffer
 * ByteBuffer buffer = ByteBuffer.wrap("Performance".getBytes(StandardCharsets.UTF_8));
 * String hex = Hex.encodeHexString(buffer);
 *
 * // Decoding with custom charset
 * Hex decoder = new Hex(StandardCharsets.UTF_8);
 * byte[] result = decoder.decode(hex);
 * </pre>
 *
 * <h2>Performance Considerations</h2>
 * <ul>
 *   <li>Use {@link java.nio.ByteBuffer} for large data sets to minimize memory copies</li>
 *   <li>Reuse {@link de.cuioss.tools.codec.Hex} instances when using custom charsets</li>
 *   <li>Prefer static methods for default UTF-8 encoding</li>
 *   <li>StringBuilder is not used internally to reduce object creation</li>
 *   <li>Direct char[] manipulation for optimal performance</li>
 * </ul>
 *
 * <h2>Best Practices</h2>
 * <ul>
 *   <li>Always specify character encoding when converting strings to bytes</li>
 *   <li>Handle {@link de.cuioss.tools.codec.DecoderException} for invalid hex strings</li>
 *   <li>Use try-with-resources for ByteBuffer operations</li>
 *   <li>Consider case sensitivity when comparing hex strings</li>
 *   <li>Validate input length before decoding (must be even)</li>
 * </ul>
 *
 * <h2>Migration from Other Libraries</h2>
 * <h3>From Apache Commons Codec</h3>
 * <pre>
 * // Apache Commons Codec
 * String hex = Hex.encodeHexString(bytes);
 * byte[] data = Hex.decodeHex(hex.toCharArray());
 *
 * // CUI Java Tools equivalent
 * String hex = de.cuioss.tools.codec.Hex.encodeHexString(bytes);
 * byte[] data = de.cuioss.tools.codec.Hex.decodeHex(hex);
 * </pre>
 *
 * <h3>From javax.xml.bind.DatatypeConverter</h3>
 * <pre>
 * // javax.xml.bind.DatatypeConverter (deprecated in Java 9+)
 * String hex = DatatypeConverter.printHexBinary(bytes);
 * byte[] data = DatatypeConverter.parseHexBinary(hex);
 *
 * // CUI Java Tools equivalent
 * String hex = de.cuioss.tools.codec.Hex.encodeHexString(bytes, true); // true for uppercase
 * byte[] data = de.cuioss.tools.codec.Hex.decodeHex(hex);
 * </pre>
 *
 * @author Oliver Wolff
 * @see de.cuioss.tools.codec.Hex
 * @see de.cuioss.tools.codec.EncoderException
 * @see de.cuioss.tools.codec.DecoderException
 */
package de.cuioss.tools.codec;
