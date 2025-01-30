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
