package de.icw.util.formatting.template.lexer;

import static com.google.common.base.Preconditions.checkNotNull;

import java.util.EnumSet;

import de.icw.util.formatting.template.FormatterSupport;
import de.icw.util.formatting.template.lexer.BracketLexer.Brackets;
import de.icw.util.formatting.template.lexer.Lexer.ExpressionLanguage;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

/**
 * @author Eugen Fischer
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class LexerBuilder {

    static final EnumSet<ExpressionLanguage> SIMPLE = EnumSet.of(
            ExpressionLanguage.SIMPLE_SQUARED_BRACKTES, ExpressionLanguage.SIMPLE_CURLY_BRACKETS,
            ExpressionLanguage.SIMPLE_ANGLE_BRACKET);

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
        checkNotNull(expLanguage, "ExpressionLanguage must not be null.");
        return new Builder(expLanguage);
    }

    /**
     * The builder class
     */
    public static final class Builder {

        private final ExpressionLanguage expl;

        private Builder(final ExpressionLanguage expLanguage) {
            expl = expLanguage;
        }

        private static Brackets getBracketsTypeFor(final ExpressionLanguage expl) {
            final Brackets type;
            switch (expl) {
                case SIMPLE_SQUARED_BRACKTES:
                    type = Brackets.SQUARED_BRACKTES;
                    break;
                case SIMPLE_CURLY_BRACKETS:
                    type = Brackets.CURLY_BRACKETS;
                    break;
                case SIMPLE_ANGLE_BRACKET:
                    type = Brackets.ANGLE_BRACKET;
                    break;
                // $CASES-OMITTED$
                default:
                    throw new IllegalArgumentException(expl
                            + " doesn't belongs to Simple expression language.");
            }
            return type;
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
                return new BracketLexer<>(source, getBracketsTypeFor(expl));
            }
            throw new IllegalArgumentException(expl
                    + " doesn't belongs to Simple expression language.");
        }

        /**
         * @param sourceType bean type
         *
         * @return Lexer for classType
         * @throws IllegalStateException if access to the class constructor fails or class isn't
         *             public
         */
        public <F extends FormatterSupport> Lexer<F> build(final Class<F> sourceType) {
            try {
                return build(sourceType.newInstance());
            } catch (final InstantiationException e) {
                throw new IllegalStateException("Class '" + sourceType + "' should provide a default constructor.", e);
            } catch (final IllegalAccessException e) {
                throw new IllegalStateException("Class '" + sourceType + "' should be public.", e);
            }
        }

    }

}
