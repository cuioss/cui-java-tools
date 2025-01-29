/**
 * Provides enhanced logging utilities built on top of Java's logging framework.
 *
 * <h2>Overview</h2>
 * <p>
 * This package offers utilities for structured logging, with support for context
 * tracking and message formatting. It provides consistent logging patterns
 * and proper error handling across the application.
 * </p>
 *
 * <h2>Key Components</h2>
 * <ul>
 *   <li><b>Core Logging</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.logging.CuiLogger} - Enhanced logging with context</li>
 *       <li>{@link de.cuioss.tools.logging.LogLevel} - Standard log levels</li>
 *       <li>{@link de.cuioss.tools.logging.LogRecord} - Structured log records</li>
 *     </ul>
 *   </li>
 * </ul>
 *
 * <h2>Usage Examples</h2>
 * <pre>
 * // 1. Setup - create logger instance
 * public class UserService {
 *     private static final CuiLogger log = new CuiLogger(UserService.class);
 * 
 *     // 2. Logging with context
 *     public void processUser(String userId, UserData data) {
 *         // Debug logging for development
 *         log.debug("Starting user processing for '%s'", userId);
 * 
 *         try {
 *             // Info for normal operation
 *             log.info("Processing user '%s' with role '%s'", 
 *                 userId, data.getRole());
 * 
 *             if (!isValid(data)) {
 *                 // Warning for potential issues
 *                 log.warn("Invalid user data for '%s'", userId);
 *                 return;
 *             }
 * 
 *             // Process user...
 * 
 *         } catch (Exception e) {
 *             // Error logging with exception
 *             log.error(e, "Failed to process user '%s'", userId);
 *             throw new ServiceException("User processing failed", e);
 *         }
 *     }
 * }
 * </pre>
 *
 * <h2>Best Practices</h2>
 * <ul>
 *   <li>Create one logger instance per class</li>
 *   <li>Use appropriate log levels:
 *     <ul>
 *       <li>DEBUG - Development information</li>
 *       <li>INFO - Normal operation</li>
 *       <li>WARN - Potential issues</li>
 *       <li>ERROR - Errors requiring attention</li>
 *     </ul>
 *   </li>
 *   <li>Always include context in messages</li>
 *   <li>Pass exceptions to error logging</li>
 * </ul>
 *
 * @author Oliver Wolff
 * @see de.cuioss.tools.logging.CuiLogger
 * @see de.cuioss.tools.logging.LogLevel
 * @see de.cuioss.tools.logging.LogRecord
 */
package de.cuioss.tools.logging;
