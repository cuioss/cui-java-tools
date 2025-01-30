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

import static java.util.Objects.requireNonNull;

import de.cuioss.tools.formatting.template.FormatterSupport;
import de.cuioss.tools.formatting.template.lexer.BracketLexer.Brackets;
import de.cuioss.tools.formatting.template.lexer.Lexer.ExpressionLanguage;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.lang.reflect.InvocationTargetException;
import java.util.EnumSet;

/**
 * @author Eugen Fischer
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class LexerBuilder {

    static final EnumSet<ExpressionLanguage> SIMPLE = EnumSet.of(ExpressionLanguage.SIMPLE_SQUARED_BRACKTES,
            ExpressionLanguage.SIMPLE_CURLY_BRACKETS, ExpressionLanguage.SIMPLE_ANGLE_BRACKET);

    /**
     * @return the builder with {@link ExpressionLanguage#SIMPLE_SQUARED_BRACKTES}
     */
    public static Builder useSimpleElWithSquaredBrackets() {
        return new Builder(ExpressionLanguage.SIMPLE_SQUARED_BRACKTES);
    }

    /**
     * @param expLanguage {@link ExpressionLanguage} must not be null
     *
     * @return builder with the given {@link ExpressionLanguage}
     */
    public static Builder withExpressionLanguage(final ExpressionLanguage expLanguage) {
        requireNonNull(expLanguage, "ExpressionLanguage must not be null.");
        return new Builder(expLanguage);
    }

    /**
     * The builder class
     */
    public static final class Builder {

        private final ExpressionLanguage expl;

        private boolean strict = false;

        private Builder(final ExpressionLanguage expLanguage) {
            expl = expLanguage;
        }

        private static Brackets getBracketsTypeFor(final ExpressionLanguage expl) {
            return switch (expl) {
                case SIMPLE_SQUARED_BRACKTES -> Brackets.SQUARED_BRACKETS;
                case SIMPLE_CURLY_BRACKETS -> Brackets.CURLY_BRACKETS;
                case SIMPLE_ANGLE_BRACKET -> Brackets.ANGLE_BRACKET;
                default -> throw new IllegalArgumentException(expl + " doesn't belongs to Simple expression language.");
            };
        }

        /**
         * @param strict enabling the strict mode for pattern matching (only match exact
         *               name) instead of best fitting
         * @return The concrete {@link Builder}
         */
        public Builder strict(boolean strict) {
            this.strict = strict;
            return this;
        }

        /**
         * Build the formatter for {@link FormatterSupport} type
         *
         * @param source {@link FormatterSupport} type
         *
         * @return created formatter
         */
        public <F extends FormatterSupport> Lexer<F> build(final F source) {
            if (SIMPLE.contains(expl)) {
                return new BracketLexer<>(source, getBracketsTypeFor(expl), strict);
            }
            throw new IllegalArgumentException(expl + " doesn't belongs to Simple expression language.");
        }

        /**
         * @param sourceType bean type
         *
         * @return Lexer for classType
         * @throws IllegalStateException if access to the class constructor fails or
         *                               class isn't public
         */
        public <F extends FormatterSupport> Lexer<F> build(final Class<F> sourceType) {
            try {
                return build(sourceType.getDeclaredConstructor().newInstance());
            } catch (final RuntimeException | InstantiationException | IllegalAccessException
                    | InvocationTargetException | NoSuchMethodException e) {
                throw new IllegalStateException(
                        "Class '" + sourceType + "' should provide an accessible default constructor.", e);
            }
        }

    }

}
