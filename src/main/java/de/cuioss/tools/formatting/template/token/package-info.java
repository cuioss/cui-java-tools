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
