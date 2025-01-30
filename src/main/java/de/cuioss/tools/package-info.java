/**
 * Core utilities and tools for Java development in the CUI ecosystem.
 *
 * <h2>Overview</h2>
 * <p>
 * The cui-java-tools library provides essential utilities and tools for Java development.
 * Built on Java 17, it offers type-safe,
 * efficient implementations that integrate seamlessly with CUI's standards.
 * </p>
 *
 * <h2>Key Features</h2>
 * <ul>
 *   <li><b>Base Utilities</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.base} - Core operations and validations</li>
 *       <li>Preconditions, string operations, and basic type handling</li>
 *     </ul>
 *   </li>
 *   <li><b>Collections</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.collect} - Enhanced collection utilities</li>
 *       <li>Type-safe builders and immutable collections</li>
 *     </ul>
 *   </li>
 *   <li><b>I/O and Resources</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.io} - File and stream operations</li>
 *       <li>Resource loading and classpath handling</li>
 *     </ul>
 *   </li>
 *   <li><b>Logging and Monitoring</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.logging} - CUI logger implementation</li>
 *       <li>Structured logging with template support</li>
 *     </ul>
 *   </li>
 *   <li><b>Enterprise Integration</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.net} - Network and SSL utilities</li>
 *       <li>{@link de.cuioss.tools.property} - Java Bean property handling</li>
 *       <li>{@link de.cuioss.tools.reflect} - Type-safe reflection support</li>
 *     </ul>
 *   </li>
 * </ul>
 *
 * <h2>Design Principles</h2>
 * <ul>
 *   <li><b>Zero Dependencies</b>
 *     <ul>
 *       <li>No external runtime dependencies</li>
 *       <li>Self-contained implementation</li>
 *     </ul>
 *   </li>
 *   <li><b>Quality Focus</b>
 *     <ul>
 *       <li>Comprehensive unit testing with JUnit 5</li>
 *       <li>Logging test coverage for INFO to FATAL levels</li>
 *     </ul>
 *   </li>
 *   <li><b>Best Practices</b>
 *     <ul>
 *       <li>Type-safe implementations</li>
 *       <li>Proper resource management</li>
 *       <li>Consistent error handling</li>
 *     </ul>
 *   </li>
 * </ul>
 *
 * <h2>Getting Started</h2>
 * <p>
 * Add the following Maven dependency to your project:
 * <pre>
 * &lt;dependency&gt;
 *     &lt;groupId&gt;de.cuioss&lt;/groupId&gt;
 *     &lt;artifactId&gt;cui-java-tools&lt;/artifactId&gt;
 *     &lt;version&gt;[current-version]&lt;/version&gt;
 * &lt;/dependency&gt;
 * </pre>
 * </p>
 *
 * <h2>Related Projects</h2>
 * <ul>
 *   <li>cui-test-juli-logger - Testing logging aspects</li>
 *   <li>cui-test-generator - Test data generation</li>
 *   <li>cui-test-value-objects - Value object testing</li>
 *   <li>cui-jsf-test-basic - JSF testing utilities</li>
 * </ul>
 *
 * @author Oliver Wolff
 * @see <a href="https://github.com/cuioss">CUI OSS Projects</a>
 * @see de.cuioss.tools.base
 * @see de.cuioss.tools.collect
 * @see de.cuioss.tools.io
 * @see de.cuioss.tools.logging
 * @see de.cuioss.tools.net
 * @see de.cuioss.tools.property
 * @see de.cuioss.tools.reflect
 */
package de.cuioss.tools;
