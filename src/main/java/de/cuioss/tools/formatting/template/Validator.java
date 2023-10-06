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

import static java.util.Objects.requireNonNull;

import java.io.Serializable;

import de.cuioss.tools.formatting.template.lexer.Lexer;
import de.cuioss.tools.formatting.template.lexer.LexerBuilder;
import lombok.NoArgsConstructor;

/**
 *
 * @param <F> at least {@link FormatterSupport}
 */
public class Validator<F extends FormatterSupport> implements Serializable {

    private static final long serialVersionUID = 8358892211840118282L;

    private final Lexer<F> lexer;

    Validator(final Lexer<F> lexer) {
        this.lexer = requireNonNull(lexer);
    }

    /**
     * @param template must not be null if template doesn't fit to el-expression or
     *                 use tokens which are not supported.
     */
    public void validate(final String template) {
        requireNonNull(template, "Template must not be null.");
        lexer.validateTemplate(template);
    }

    /**
     * @return an {@link ValidatorBuilder}
     */
    public static <E extends FormatterSupport> ValidatorBuilder<E> builder() {
        return new ValidatorBuilder<>();
    }

    /**
     * This method provide only validation of simple expression language with
     * squared brackets. If some other expression language is used on the template
     * validation will fail. If there is a need for usage of other expression
     * language use {@link #validateTemplate(String, Lexer)}
     *
     * @param template input which should be validated
     * @param source   source must not be null
     */
    public static <E extends FormatterSupport> void validateTemplate(final String template, final E source) {
        new Validator.ValidatorBuilder<E>().forSource(source).validate(template);
    }

    /**
     * This method provide only validation of simple expression language with
     * squared brackets. If some other expression language is used on the template
     * validation will fail. If there is a need for usage of other expression
     * language use {@link #validateTemplate(String, Lexer)}
     *
     * @param template input which should be validated
     * @param source   target type must not be null
     */
    public static <E extends FormatterSupport> void validateTemplate(final String template, final Class<E> source) {
        new Validator.ValidatorBuilder<E>().forType(source).validate(template);
    }

    /**
     * This method provide validation for template of specific expression language.
     * Therefore, you need to provide a fitting Lexer.
     *
     * @param template input which should be validated
     * @param lexer    {@link Lexer} for usage of specific expression language on
     *                 template
     */
    public static <E extends FormatterSupport> void validateTemplate(final String template, final Lexer<E> lexer) {
        new Validator.ValidatorBuilder<E>().withLexer(lexer).validate(template);
    }

    @NoArgsConstructor
    public static final class ValidatorBuilder<E extends FormatterSupport> {

        private Lexer<E> lexer;

        public Validator<E> forType(final Class<E> source) {
            if (null == lexer) {
                lexer = useSimpleElWithSquaredBrackets(source);
            }
            return new Validator<>(lexer);
        }

        public Validator<E> withLexer(final Lexer<E> lexerInstance) {
            return new Validator<>(lexerInstance);
        }

        public Validator<E> forSource(E source) {
            if (null == lexer) {
                lexer = useSimpleElWithSquaredBrackets(source);
            }
            return new Validator<>(lexer);
        }

        private Lexer<E> useSimpleElWithSquaredBrackets(final Class<E> source) {
            return LexerBuilder.useSimpleElWithSquaredBrackets().build(source);
        }

        private Lexer<E> useSimpleElWithSquaredBrackets(E source) {
            return LexerBuilder.useSimpleElWithSquaredBrackets().build(source);
        }

    }
}
