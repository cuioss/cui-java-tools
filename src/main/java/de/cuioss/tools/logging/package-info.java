/**
 * Provides enhanced logging utilities built on top of Java's logging framework.
 *
 * <h2>Overview</h2>
 * <p>
 * This package offers utilities for structured logging, with support for context
 * tracking, message formatting.
 * It integrates with Java's logging framework while providing additional features for enterprise
 * applications.
 * </p>
 *
 * <h2>Key Components</h2>
 * <ul>
 *   <li><b>Core Logging</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.logging.CuiLogger} - Enhanced logging</li>
 *       <li>{@link de.cuioss.tools.logging.LogRecord} - Log record handling</li>
 *       <li>Message formatting and context tracking</li>
 *     </ul>
 *   </li>
 * </ul>
 *
 * <h2>Usage Examples</h2>
 * <pre>
 * // Basic logging
 * CuiLogger logger = new CuiLogger(MyClass.class);
 * logger.info("Processing request {}", requestId);
 *
 * // Error logging with context
 * try {
 *     processData();
 * } catch (Exception e) {
 *     logger.error("Failed to process data", e);
 * }
 *
 * </pre>
 *
 * <h2>Best Practices</h2>
 * <ul>
 *   <li>Use appropriate log levels</li>
 *   <li>Include relevant context in log messages</li>
 *   <li>Handle exceptions properly</li>
 *   <li>Use lazy evaluation for expensive operations</li>
 * </ul>
 *
 * @author Oliver Wolff
 * @see de.cuioss.tools.logging.CuiLogger
 * @see de.cuioss.tools.logging.LogLevel
 * @see de.cuioss.tools.logging.LogRecord
 */
package de.cuioss.tools.logging;
