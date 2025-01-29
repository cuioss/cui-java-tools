/**
 * Provides utilities for string manipulation, joining, splitting, and text processing.
 *
 * <h2>Overview</h2>
 * <p>
 * This package offers comprehensive string handling utilities designed for efficient
 * text processing.
 * It provides type-safe operations with proper null handling and performance optimization.
 * </p>
 *
 * <h2>Key Components</h2>
 * <ul>
 *   <li><b>String Operations</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.string.MoreStrings} - Enhanced string utilities</li>
 *       <li>Null-safe string operations</li>
 *       <li>String formatting with '%s' placeholders</li>
 *       <li>Common string transformations</li>
 *     </ul>
 *   </li>
 *   <li><b>String Joining</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.string.Joiner} - Flexible string joining</li>
 *       <li>Customizable separators and handling of null values</li>
 *     </ul>
 *   </li>
 *   <li><b>String Splitting</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.string.Splitter} - String splitting utilities</li>
 *       <li>{@link de.cuioss.tools.string.TextSplitter} - Text content splitting. Usually for display within HTML-Context</li>
 *     </ul>
 *   </li>
 * </ul>
 *
 * <h2>Usage Examples</h2>
 * <pre>
 * // 1. Setup - import required classes
 * import de.cuioss.tools.string.MoreStrings;
 * import de.cuioss.tools.string.Joiner;
 * import de.cuioss.tools.logging.CuiLogger;
 *
 * private static final CuiLogger log = new CuiLogger(MyService.class);
 *
 * // 2. String operations with logging
 * public void processString(String input) {
 *     try {
 *         // Null-safe string checks
 *         if (MoreStrings.isEmpty(input)) {
 *             log.debug("Input is empty, using default");
 *             input = getDefaultValue();
 *         }
 *
 *         // String formatting
 *         String message = MoreStrings.lenientFormat(
 *             "Processing input: '%s'", input);
 *         log.info(message);
 *
 *     } catch (IllegalArgumentException e) {
 *         log.error(e, "Error processing input: '%s'", input);
 *         throw e;
 *     }
 * }
 *
 * // 3. String joining
 *    return Joiner.on(",").skipNulls().join(elements);
 *
 * }
 * </pre>
 *
 * <h2>Best Practices</h2>
 * <ul>
 *   <li>Always use null-safe operations</li>
 *   <li>Handle empty strings appropriately</li>
 * </ul>
 *
 * @author Oliver Wolff
 * @see de.cuioss.tools.string.MoreStrings
 * @see de.cuioss.tools.string.Joiner
 * @see de.cuioss.tools.string.Splitter
 * @see de.cuioss.tools.logging.CuiLogger
 */
package de.cuioss.tools.string;
