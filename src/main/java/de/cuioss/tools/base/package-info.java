/**
 * Core utility classes for fundamental operations and validations in the CUI ecosystem.
 *
 * <h2>Overview</h2>
 * <p>
 * This package provides essential utility classes for basic operations and validations.
 * The utilities focus on type safety, proper error handling, and integration with CUI's logging standards.
 * </p>
 *
 * <h2>Key Components</h2>
 * <ul>
 *   <li><b>Preconditions</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.base.Preconditions} - Argument and state validation</li>
 *       <li>Inspired by Google Guava's Preconditions</li>
 *       <li>Support for formatted error messages using '%s' placeholders</li>
 *       <li>Throws {@link java.lang.IllegalArgumentException} or {@link java.lang.IllegalStateException} dependent on the function</li>
 *     </ul>
 *   </li>
 *   <li><b>Boolean Operations</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.base.BooleanOperations} - Boolean array operations</li>
 *       <li>Methods for checking any/all true/false conditions</li>
 *       <li>Support for null and empty array handling</li>
 *     </ul>
 *   </li>
 * </ul>
 *
 * <h2>Usage Examples</h2>
 * <pre>
 *     Preconditions.checkArgument(StringUtils.isNotEmpty(userId),
 *         "UserId must not be empty");
 *
 * </pre>
 *
 * <h2>Best Practices</h2>
 * <ul>
 *   <li>Include context in error messages</li>
 * </ul>
 *
 * @author Oliver Wolff
 * @see de.cuioss.tools.base.Preconditions
 * @see de.cuioss.tools.base.BooleanOperations
 * @see de.cuioss.tools.logging.CuiLogger
 */
package de.cuioss.tools.base;