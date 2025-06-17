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
