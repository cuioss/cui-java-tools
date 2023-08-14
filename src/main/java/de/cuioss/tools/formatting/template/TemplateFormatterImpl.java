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
package de.cuioss.tools.formatting.template;

import static de.cuioss.tools.base.Preconditions.checkState;
import static java.util.Objects.requireNonNull;

import java.util.ArrayList;
import java.util.List;

import de.cuioss.tools.formatting.template.lexer.Lexer;
import de.cuioss.tools.formatting.template.lexer.LexerBuilder;
import de.cuioss.tools.formatting.template.token.Token;
import lombok.EqualsAndHashCode;
import lombok.Synchronized;
import lombok.ToString;

/**
 * Formatter which is able to replace parameter inside the template based on
 * {@link FormatterSupport} information. See {@link de.cuioss.tools.formatting}
 * for details.
 *
 * @param <T> at least {@link FormatterSupport}
 *
 * @author Eugen Fischer
 */
@ToString
@EqualsAndHashCode
public final class TemplateFormatterImpl<T extends FormatterSupport> implements TemplateFormatter<T> {

    private static final long serialVersionUID = -6297959581838201331L;

    private final String template;

    private ArrayList<Token> parsedTokens;

    private Lexer<T> lexer;

    private final boolean strict;

    private TemplateFormatterImpl(final String template, final boolean strict) {
        this.template = template;
        this.strict = strict;
    }

    /**
     * Lexer which should be used to scan the template
     *
     * @param lexerInstance must not be {@code null}
     *
     * @return reference to TemplateFormatter, fluent api style
     */
    TemplateFormatterImpl<T> scanBy(final Lexer<T> lexerInstance) {
        lexer = requireNonNull(lexerInstance, "Parser must not be null");
        parsedTokens = null;
        return this;
    }

    /**
     * replace attributes from template by attribute values from the map. missing
     * template attributes will be ignored and doesn't add to result at all.
     *
     * @param reference must not be null
     *
     * @return completed template
     */
    @Override
    public String format(final T reference) {

        requireNonNull(reference, "Reference must not be null");

        final var tokenList = getParsedTokens();

        final var buffer = new StringBuilder(0);

        for (var index = 0; index < tokenList.size(); index++) {
            final var token = tokenList.get(index);
            if (token.isStringToken()) {
                if (lookUpLastTokenHasValue(tokenList, reference, index)
                        && lookUpNextTokenHasValue(tokenList, reference, index)) {
                    buffer.append(token.substituteAttribute(reference));
                }
            } else {
                buffer.append(token.substituteAttribute(reference));
            }
        }

        return buffer.toString();
    }

    private boolean lookUpNextTokenHasValue(final List<Token> tokenList, final T reference,
            final int currentTokenIndex) {

        var nextTokenIndex = currentTokenIndex + 1;
        while (nextTokenIndex < tokenList.size()) {
            final var token = tokenList.get(nextTokenIndex);
            if (!token.isStringToken()) {
                final var value = token.substituteAttribute(reference);
                if (!value.isEmpty()) {
                    return true;
                }
            }
            nextTokenIndex++;
        }
        return false;
    }

    private boolean lookUpLastTokenHasValue(final List<Token> tokenList, final T reference,
            final int currentTokenIndex) {

        var result = false;
        final var lastTokenIndex = currentTokenIndex - 1;
        if (lastTokenIndex >= 0) {
            final var value = tokenList.get(lastTokenIndex).substituteAttribute(reference);
            result = !value.isEmpty();
        }
        return result;
    }

    @Synchronized
    private List<Token> getParsedTokens() {
        if (null == this.parsedTokens) {
            checkState(null != this.lexer, "Parser must be initialized before.");
            this.parsedTokens = new ArrayList<>(this.lexer.scan(this.template));
        }
        return this.parsedTokens;
    }

    /**
     * The created TemplateFormatter provide only usage of simple expression
     * language with squared brackets.
     *
     * @param template   must not be null
     * @param sourceType must not be null
     *
     * @return TemplateFormatter which using template and lexer which was forwarded
     */
    public static <F extends FormatterSupport> TemplateFormatter<F> createFormatter(final String template,
            final Class<F> sourceType) {
        return TemplateBuilder.useTemplate(template).forType(sourceType);
    }

    /**
     * @param template must not be null
     * @param source   must not be null
     *
     * @return TemplateFormatter
     */
    public static <F extends FormatterSupport> TemplateFormatter<F> createFormatter(final String template,
            final F source) {
        return TemplateBuilder.useTemplate(template).forSource(source);
    }

    /**
     * @param template must not be null
     * @param lexer    must not be null
     *
     * @return TemplateFormatter which using template and lexer which was forwarded
     */
    public static <F extends FormatterSupport> TemplateFormatter<F> createFormatter(final String template,
            final Lexer<F> lexer) {
        return TemplateBuilder.useTemplate(template).scanBy(lexer);
    }

    /**
     * The created TemplateFormatter provide only usage of simple expression
     * language with squared brackets.
     *
     * @param template   must not be null
     * @param sourceType must not be null
     * @param strict     use strict mode for pattern matching (only match exact
     *                   name) instead of best fitting
     *
     * @return TemplateFormatter which using template and lexer which was forwarded
     */
    public static <F extends FormatterSupport> TemplateFormatter<F> createFormatter(final String template,
            final Class<F> sourceType, final boolean strict) {
        return TemplateBuilder.useTemplate(template).strict(strict).forType(sourceType);
    }

    /**
     * @param template must not be null
     * @param source   must not be null
     * @param strict   use strict mode for pattern matching (only match exact name)
     *                 instead of best fitting
     *
     * @return TemplateFormatter
     */
    public static <F extends FormatterSupport> TemplateFormatter<F> createFormatter(final String template,
            final F source, final boolean strict) {
        return TemplateBuilder.useTemplate(template).strict(strict).forSource(source);
    }

    /**
     * @param template must not be null
     * @param lexer    must not be null
     * @param strict   use strict mode for pattern matching (only match exact name)
     *                 instead of best fitting
     *
     * @return TemplateFormatter which using template and lexer which was forwarded
     */
    public static <F extends FormatterSupport> TemplateFormatter<F> createFormatter(final String template,
            final Lexer<F> lexer, final boolean strict) {
        return TemplateBuilder.useTemplate(template).strict(strict).scanBy(lexer);
    }

    /**
     * @return a newly created {@link TemplateBuilder}
     */
    @SuppressWarnings("squid:S2440") // owolff: False positive
    public static TemplateBuilder builder() {
        return new TemplateBuilder();
    }

    /**
     * Template Builder
     *
     * @author Eugen Fischer
     */
    public static final class TemplateBuilder {

        private TemplateBuilder() {
        }

        static FormatterBuilder useTemplate(final String template) {
            return new FormatterBuilder(template);
        }

        static final class FormatterBuilder {

            private final String template;

            private boolean strict;

            FormatterBuilder(final String templateInput) {
                template = templateInput;
            }

            /**
             * @param strict use strict mode for pattern matching (only match exact name)
             *               instead of best fitting
             * @return a {@link FormatterBuilder} with strict set to given parameter
             */
            public FormatterBuilder strict(boolean strict) {
                this.strict = strict;
                return this;
            }

            public <F extends FormatterSupport> TemplateFormatter<F> scanBy(final Lexer<F> lexer) {
                return new TemplateFormatterImpl<F>(template, strict).scanBy(lexer);
            }

            public <F extends FormatterSupport> TemplateFormatter<F> forSource(final F source) {
                final Lexer<F> lexer = LexerBuilder.useSimpleElWithSquaredBrackets().strict(strict).build(source);
                return scanBy(lexer);
            }

            public <F extends FormatterSupport> TemplateFormatter<F> forType(final Class<F> classType) {
                final Lexer<F> lexer = LexerBuilder.useSimpleElWithSquaredBrackets().strict(strict).build(classType);
                return scanBy(lexer);
            }
        }
    }
}
