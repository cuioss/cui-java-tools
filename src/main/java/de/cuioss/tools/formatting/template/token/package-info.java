/**
 * Provides token classes for template parsing and formatting.
 * <h2>Overview</h2>
 * <p>
 * This package contains the token types used in template processing:
 * </p>
 * <ul>
 *   <li>{@link de.cuioss.tools.formatting.template.token.Token} - Base interface for all tokens</li>
 *   <li>{@link de.cuioss.tools.formatting.template.token.StringToken} - Represents static text in templates</li>
 *   <li>{@link de.cuioss.tools.formatting.template.token.ActionToken} - Represents dynamic property placeholders</li>
 * </ul>
 * 
 * <h2>Token Types</h2>
 * <p>
 * The template parser generates two main types of tokens:
 * </p>
 * <ol>
 *   <li><strong>String Tokens</strong> - Represent literal text that appears as-is in the output</li>
 *   <li><strong>Action Tokens</strong> - Represent property placeholders that will be replaced with actual values</li>
 * </ol>
 * 
 * <h2>Usage Example</h2>
 * <pre>
 * // A template like "[firstName] [lastName]" would be tokenized into:
 * List&lt;Token&gt; tokens = Arrays.asList(
 *     new ActionToken("firstName"),
 *     new StringToken(" "),
 *     new ActionToken("lastName")
 * );
 * </pre>
 * 
 * @see de.cuioss.tools.formatting.template.token.Token
 * @see de.cuioss.tools.formatting.template.token.StringToken
 * @see de.cuioss.tools.formatting.template.token.ActionToken
 */
package de.cuioss.tools.formatting.template.token;
