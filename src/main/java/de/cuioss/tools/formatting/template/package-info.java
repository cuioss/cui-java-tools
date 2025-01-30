/**
 * Provides the core template formatting functionality for the CUI formatting framework.
 * <h2>Overview</h2>
 * <p>
 * This package contains the core components for template-based formatting:
 * </p>
 * <ul>
 *   <li>{@link de.cuioss.tools.formatting.template.FormatterSupport} - Interface for objects that can be formatted</li>
 *   <li>{@link de.cuioss.tools.formatting.template.TemplateFormatter} - Interface for formatting objects using templates</li>
 *   <li>{@link de.cuioss.tools.formatting.template.TemplateFormatterImpl} - Default implementation of TemplateFormatter</li>
 *   <li>{@link de.cuioss.tools.formatting.template.TemplateManager} - Manages template configurations</li>
 * </ul>
 * 
 * <h2>Template Syntax</h2>
 * <p>
 * The template syntax uses square brackets to denote property placeholders:
 * <pre>
 * [propertyName]
 * </pre>
 * Properties must be defined in the {@link de.cuioss.tools.formatting.template.FormatterSupport} implementation.
 * </p>
 * 
 * <h2>Usage Example</h2>
 * <pre>
 * TemplateFormatter&lt;MyObject&gt; formatter = TemplateFormatterImpl.builder()
 *     .useTemplate("[property1], [property2]")
 *     .forType(MyObject.class)
 *     .build();
 * String result = formatter.format(myObject);
 * </pre>
 * 
 * @see de.cuioss.tools.formatting.template.FormatterSupport
 * @see de.cuioss.tools.formatting.template.TemplateFormatter
 */
package de.cuioss.tools.formatting.template;
