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
 *       <li>Throws {@link java.lang.IllegalArgumentException} or {@link java.lang.IllegalStateException}</li>
 *     </ul>
 *   </li>
 *   <li><b>Boolean Operations</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.base.BooleanOperations} - Boolean array operations</li>
 *       <li>Methods for checking any/all true/false conditions</li>
 *       <li>Support for null and empty array handling</li>
 *       <li>Boolean string validation</li>
 *     </ul>
 *   </li>
 * </ul>
 *
 * <h2>Usage Examples</h2>
 * <pre>
 * // Precondition checks with logging
 * public void processUser(String userId, UserData data) {
 *     Preconditions.checkArgument(StringUtils.isNotEmpty(userId),
 *         "UserId must not be empty");
 *     Preconditions.checkState(isInitialized(),
 *         "Service must be initialized, current state: %s", getState());
 *
 *     // Process with proper logging
 *     LOGGER.info("Processing user '%s'", userId);
 *     try {
 *         // Processing logic
 *     } catch (Exception e) {
 *         LOGGER.error(e, "Error processing user '%s'", userId);
 *         throw e;
 *     }
 * }
 *
 * // Boolean operations
 * boolean[] conditions = {true, false, true};
 * if (BooleanOperations.isAnyTrue(conditions)) {
 *     LOGGER.info("At least one condition is true");
 * }
 *
 * // Boolean validation
 * String input = "TRUE";
 * if (BooleanOperations.isValidBoolean(input)) {
 *     // Process valid boolean string
 * }
 * </pre>
 *
 * <h2>Best Practices</h2>
 * <ul>
 *   <li>Use '%s' for string substitutions in messages</li>
 *   <li>Include descriptive error messages in precondition checks</li>
 * </ul>
 *
 * @author Oliver Wolff
 * @see de.cuioss.tools.base.Preconditions
 * @see de.cuioss.tools.base.BooleanOperations
 */
package de.cuioss.tools.base;