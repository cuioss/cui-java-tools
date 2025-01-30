/*
 * Copyright 2023 the original author or authors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.tools.formatting.template.lexer;

import static de.cuioss.tools.base.Preconditions.checkArgument;
import static de.cuioss.tools.collect.CollectionLiterals.immutableList;
import static de.cuioss.tools.string.MoreStrings.isEmpty;
import static java.util.Objects.requireNonNull;

import de.cuioss.tools.formatting.template.FormatterSupport;
import de.cuioss.tools.formatting.template.token.Token;
import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import java.io.Serial;
import java.io.Serializable;
import java.util.List;

/**
 * Functionality of scanning plain text and split this to tokens
 *
 * @param <T> bounds lexer to one type to avoid cross using accidentally
 * @author Eugen Fischer
 */
@ToString
@EqualsAndHashCode
public abstract class Lexer<T extends FormatterSupport> implements Serializable {

    @Serial
    private static final long serialVersionUID = 8645233576605974741L;

    @Getter(AccessLevel.PROTECTED)
    private final List<String> tokenList;

    /**
     * Constructor of Lexer. Source provide information of "tokens" which he
     * supports. Therefore {@link FormatterSupport#getSupportedPropertyNames()} will
     * be used.
     *
     * @param source must not be null
     * @throws NullPointerException     if source is missing
     * @throws IllegalArgumentException if attribute is null or empty
     */
    protected Lexer(final T source) {
        requireNonNull(source, "Source must not be null");
        tokenList = immutableList(requireNonNull(source.getSupportedPropertyNames()));
        for (final String attribute : tokenList) {
            checkArgument(!isEmpty(attribute), "Attributes must not be null or empty. '" + tokenList + "'");
        }
    }

    /**
     * Throw IllegalArgumentException with information about wrong token and
     * supported tokens
     *
     * @param wrongToken    must not be null
     * @param allowedTokens must not be null
     */
    protected static final void throwUnsupportedTokenException(final String wrongToken,
            final List<String> allowedTokens) {
        final var builder = new StringBuilder();
        builder.append("Unsupported token '").append(wrongToken).append("' was detected.\n").append("Allowed are :\n");
        for (final String allowedToken : allowedTokens) {
            builder.append(" - ").append(allowedToken).append("\n");
        }
        throw new IllegalArgumentException(builder.toString());
    }

    /**
     * Parse template into Token List according attribute list
     *
     * @param input template string
     * @return created list of token, list could be empty if input template is null
     *         or empty
     * @throws IllegalArgumentException if template include unknown token, or
     *                                  doesn't fit the rules
     */
    public abstract List<Token> scan(final String input);

    /**
     * Validate template by scan this
     *
     * @param input to be validated
     */
    public final void validateTemplate(final String input) {
        scan(input);
    }

    /**
     * Supported expression language
     */
    public enum ExpressionLanguage {
        /** {@code [attribute1][attribute2]..[attribute n]} */
        SIMPLE_SQUARED_BRACKTES,
        /** {attribute1}{attribute2}..{attribute n} */
        SIMPLE_CURLY_BRACKETS,
        /** {@code <attribute1><attribute2>..<attribute n>} */
        SIMPLE_ANGLE_BRACKET,
        /**
         * usage of String Template Expression Language
         *
         * @see <a href=
         *      "http://www.antlr.org/wiki/display/ST/StringTemplate+3+Documentation">
         *      Documentation</a>
         */
        STEL
    }

}
