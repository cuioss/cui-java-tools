/*
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
 * Provides lexical analysis functionality for template parsing.
 * <h2>Overview</h2>
 * <p>
 * This package contains the lexer components that analyze and tokenize template strings:
 * </p>
 * <ul>
 *   <li>{@link de.cuioss.tools.formatting.template.lexer.Lexer} - Core interface for template lexical analysis</li>
 *   <li>{@link de.cuioss.tools.formatting.template.lexer.BracketLexer} - Lexer implementation for bracket-based templates</li>
 *   <li>{@link de.cuioss.tools.formatting.template.lexer.LexerBuilder} - Builder for creating lexer instances</li>
 * </ul>
 * 
 * <h2>Lexer Process</h2>
 * <p>
 * The lexer breaks down template strings into tokens that can be processed by the formatter:
 * </p>
 * <ol>
 *   <li>Identifies property placeholders (e.g., [propertyName])</li>
 *   <li>Separates static text from dynamic content</li>
 *   <li>Creates appropriate token objects for each part</li>
 * </ol>
 * 
 * <h2>Usage Example</h2>
 * <pre>
 * Lexer lexer = LexerBuilder.create()
 *     .withTemplate("[firstName] [lastName]")
 *     .build();
 * List&lt;Token&gt; tokens = lexer.tokenize();
 * </pre>
 * 
 * @author Eugen Fischer
 * @see de.cuioss.tools.formatting.template.lexer.Lexer
 * @see de.cuioss.tools.formatting.template.lexer.BracketLexer
 */
package de.cuioss.tools.formatting.template.lexer;
