/**
 * Provides utilities for handling Java properties and bean properties.
 *
 * <h2>Overview</h2>
 * This package offers utilities for working with properties, focusing on type-safe
 * property access and manipulation. It provides comprehensive property management 
 * capabilities while maintaining compatibility with Java Bean standards.
 *
 * <h2>Key Components</h2>
 * <ul>
 *   <li><b>Property Management</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.property.PropertyHolder} - Type-safe property container</li>
 *       <li>{@link de.cuioss.tools.property.PropertyUtil} - Reflection-based property access</li>
 *       <li>Support for Java Bean specification compliant properties</li>
 *     </ul>
 *   </li>
 *   <li><b>Property Metadata</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.property.PropertyMemberInfo} - Object identity and serialization</li>
 *       <li>{@link de.cuioss.tools.property.PropertyReadWrite} - Read/write access control</li>
 *       <li>Comprehensive property validation</li>
 *     </ul>
 *   </li>
 * </ul>
 *
 * <h2>Usage Examples</h2>
 * Reading a property:
 * <pre>{@code
 * // Read a property value
 * Object value = PropertyUtil.readProperty(bean, "propertyName");
 * 
 * // Create a type-safe property holder
 * Optional<PropertyHolder> holder = PropertyHolder.from(beanClass, "propertyName");
 * }</pre>
 *
 * <h2>Best Practices</h2>
 * <ul>
 *   <li>Use {@link PropertyHolder} for type-safe property access</li>
 *   <li>Prefer standard getter/setter methods over reflection</li>
 *   <li>Handle property access exceptions appropriately</li>
 * </ul>
 *
 * @author Oliver Wolff
 * @see de.cuioss.tools.property.PropertyHolder
 * @see de.cuioss.tools.property.PropertyUtil
 * @see de.cuioss.tools.property.PropertyReadWrite
 */
package de.cuioss.tools.property;
