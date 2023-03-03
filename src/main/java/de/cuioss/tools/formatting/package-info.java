/**
 * <h2>Configurable formatting for complex structures</h2>
 * <h3>The Problem</h3>
 * <p>
 * Provide a text representation for given complex object. As a plus the formatting should be easily
 * configurable with a simple DSL-style template language.
 * <h3>The Solution</h3>
 * <p>
 * The {@link de.cuioss.tools.formatting} framework presented here.
 * </p>
 * <p>
 * The starting point is {@link de.cuioss.tools.formatting.template.FormatterSupport} providing two
 * methods:
 * <ul>
 * <li>{@link de.cuioss.tools.formatting.template.FormatterSupport#getSupportedPropertyNames()}:
 * Provides the property names that can be used for formatting</li>
 * <li>{@link de.cuioss.tools.formatting.template.FormatterSupport#getAvailablePropertyValues()}:
 * Provides a name with with the supported names and values.</li>
 * </ul>
 * <p>
 * The other interface needed is {@link de.cuioss.tools.formatting.template.TemplateFormatter} defining
 * the method
 * {@link de.cuioss.tools.formatting.template.TemplateFormatter#format(de.cuioss.tools.formatting.template.FormatterSupport)}
 * doing the actual formatting.
 * </p>
 * <h3>Sample</h3>
 * Dto PersonName implementing {@link de.cuioss.tools.formatting.template.FormatterSupport}
 *
 * <pre>
 * <code>

 final PersonName personName = PersonName.builder()
 .setFamilyName("Fischers")
 .setGivenName("Fritz")
 .setMiddleName("Felix")
 .setGivenNameSuffix("Dr.")
 .build();

 final TemplateFormatter&lt;PersonName&gt; formatter = TemplateFormatterImpl.builder()
 .useTemplate("[familyName], [givenName], [middleName] [givenNameSuffix]")
 .forType(PersonName.class);

 assertEquals("Fischers, Fritz, Felix Dr.", formatter.format(personName));
 * </code>
 *
 * </pre>
 *
 */
package de.cuioss.tools.formatting;
