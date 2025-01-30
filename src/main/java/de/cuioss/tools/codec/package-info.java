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
 *     </ul>
 *   </li>
 *   <li><b>Exception Handling</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.codec.EncoderException} - For encoding errors</li>
 *       <li>{@link de.cuioss.tools.codec.DecoderException} - For decoding errors</li>
 *     </ul>
 *   </li>
 * </ul>
 *
 * <h2>Usage Examples</h2>
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
 *
 * </pre>
 *
 * <h2>Best Practices</h2>
 * <ul>
 *   <li>Always specify character encoding when converting strings to bytes</li>
 *   <li>Handle DecoderException for invalid hex strings</li>
 * </ul>
 *
 * @author Oliver Wolff
 * @see de.cuioss.tools.codec.Hex
 * @see de.cuioss.tools.codec.EncoderException
 * @see de.cuioss.tools.codec.DecoderException
 */
package de.cuioss.tools.codec;
