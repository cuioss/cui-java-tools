/**
 * Provides utilities for concurrent programming and performance measurement.
 *
 * <h2>Overview</h2>
 * <p>
 * This package offers utilities for handling concurrent operations and measuring
 * execution time in Java applications.
 * It provides thread-safe implementations and integration with CUI's logging standards.
 * </p>
 *
 * <h2>Key Components</h2>
 * <ul>
 *   <li><b>Concurrent Tools</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.concurrent.ConcurrentTools} - Thread management utilities</li>
 *
 *     </ul>
 *   </li>
 *   <li><b>Performance Measurement</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.concurrent.StopWatch} - Time measurement utility</li>
 *       <li>Precise elapsed time tracking</li>
 *       <li>Support for split times</li>
 *     </ul>
 *   </li>
 * </ul>
 *
 * <h2>Usage Examples</h2>
 * <pre>
 * // Using StopWatch for performance measurement
 * StopWatch watch = new StopWatch();
 * try {
 *     // Perform operation
 *     someOperation();
 *
 *     LOGGER.info("Operation completed in %s ms",
 *         watch.getElapsedMilliseconds());
 * } catch (Exception e) {
 *     LOGGER.error(e, "Operation failed after %s ms",
 *         watch.getElapsedMilliseconds());
 *     throw e;
 * }
 *
 * </pre>
 *
 * <h2>Best Practices</h2>
 * <ul>
 *   <li>Always handle InterruptedException properly</li>
 *   <li>Use StopWatch for detailed performance tracking</li>
 *   <li>Log performance metrics at appropriate levels</li>
 *   <li>Consider thread safety in concurrent operations</li>
 * </ul>
 *
 * @author Oliver Wolff
 * @see de.cuioss.tools.concurrent.ConcurrentTools
 * @see de.cuioss.tools.concurrent.StopWatch
 * @see de.cuioss.tools.concurrent.Ticker
 */
package de.cuioss.tools.concurrent;
