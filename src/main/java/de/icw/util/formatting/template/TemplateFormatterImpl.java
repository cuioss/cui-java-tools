package de.icw.util.formatting.template;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

import java.util.ArrayList;
import java.util.List;

import com.google.common.collect.Lists;
import de.icw.util.formatting.template.lexer.Lexer;
import de.icw.util.formatting.template.lexer.LexerBuilder;
import de.icw.util.formatting.template.token.Token;
import lombok.EqualsAndHashCode;
import lombok.Synchronized;
import lombok.ToString;

/**
 * Formatter which is able to replace parameter inside the template based on
 * {@link FormatterSupport} information. See {@link de.icw.util.formatting} for details.
 *
 * @param <T>
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

    private TemplateFormatterImpl(final String template) {
        this.template = template;
    }

    /**
     * Lexer which should be used to scan the template
     *
     * @param lexerInstance must not be {@code null}
     *
     * @return reference to TemplateFormatter, fluent api style
     */
    TemplateFormatterImpl<T> scanBy(final Lexer<T> lexerInstance) {
        this.lexer = checkNotNull(lexerInstance, "Parser must not be null");
        this.parsedTokens = null;
        return this;
    }

    /**
     * replace attributes from template by attribute values from the map.
     * missing template attributes will be ignored and doesn't add to result at
     * all.
     *
     * @param reference must not be null
     *
     * @return completed template
     */
    @Override
    public String format(final T reference) {

        checkNotNull(reference, "Reference must not be null");

        final List<Token> tokenList = getParsedTokens();

        final StringBuilder buffer = new StringBuilder();

        for (int index = 0; index < tokenList.size(); index++) {
            final Token token = tokenList.get(index);
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

        int nextTokenIndex = currentTokenIndex + 1;
        while (nextTokenIndex < tokenList.size()) {
            final Token token = tokenList.get(nextTokenIndex);
            if (!token.isStringToken()) {
                final String value = token.substituteAttribute(reference);
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

        boolean result = false;
        final int lastTokenIndex = currentTokenIndex - 1;
        if (lastTokenIndex >= 0) {
            final String value = tokenList.get(lastTokenIndex).substituteAttribute(reference);
            result = !value.isEmpty();
        }
        return result;
    }

    @Synchronized
    private List<Token> getParsedTokens() {
        if (null == this.parsedTokens) {
            checkState(null != this.lexer, "Parser must be initialized before.");
            this.parsedTokens = Lists.newArrayList(this.lexer.scan(this.template));
        }
        return this.parsedTokens;
    }

    /**
     * The created TemplateFormatter provide only usage of simple expression
     * language with squared brackets.
     *
     * @param template must not be null
     * @param sourceType must not be null
     *
     * @return TemplateFormatter which using template and lexer which was
     *         forwarded
     */
    public static <F extends FormatterSupport> TemplateFormatter<F> createFormatter(
            final String template,
            final Class<F> sourceType) {
        return Builder.useTemplate(template).forType(sourceType);
    }

    /**
     * @param template must not be null
     * @param source must not be null
     *
     * @return TemplateFormatter
     */
    public static <F extends FormatterSupport> TemplateFormatter<F> createFormatter(
            final String template,
            final F source) {
        return Builder.useTemplate(template).forSource(source);
    }

    /**
     * @param template must not be null
     * @param lexer must not be null
     *
     * @return TemplateFormatter which using template and lexer which was
     *         forwarded
     */
    public static <F extends FormatterSupport> TemplateFormatter<F> createFormatter(
            final String template,
            final Lexer<F> lexer) {
        return Builder.useTemplate(template).scanBy(lexer);
    }

    /**
     * Template Builder
     *
     * @author Eugen Fischer
     */
    public static final class Builder {

        private Builder() {
        }

        static FormatterBuilder useTemplate(final String template) {
            return new FormatterBuilder(template);
        }

        private static final class FormatterBuilder {

            private final String template;

            FormatterBuilder(final String templateInput) {
                template = templateInput;
            }

            public <F extends FormatterSupport> TemplateFormatter<F> scanBy(final Lexer<F> lexer) {
                return new TemplateFormatterImpl<F>(template).scanBy(lexer);
            }

            public <F extends FormatterSupport> TemplateFormatter<F> forSource(final F source) {
                final Lexer<F> lexer = LexerBuilder.useSimpleElWithSquaredBrackets().build(source);
                return this.scanBy(lexer);
            }

            public <F extends FormatterSupport> TemplateFormatter<F> forType(
                    final Class<F> classType) {
                final Lexer<F> lexer =
                    LexerBuilder.useSimpleElWithSquaredBrackets().build(classType);
                return scanBy(lexer);
            }
        }
    }
}
