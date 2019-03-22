package de.icw.util.formatting.template.lexer;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Strings.isNullOrEmpty;

import java.util.ArrayList;
import java.util.List;

import com.google.common.base.Splitter;
import com.google.common.collect.Lists;

import de.icw.util.formatting.template.FormatterSupport;
import de.icw.util.formatting.template.token.ActionToken;
import de.icw.util.formatting.template.token.StringToken;
import de.icw.util.formatting.template.token.Token;
import lombok.EqualsAndHashCode;
import lombok.ToString;

/**
 * Simple lexer which supports parsing of template pattern where attributes are separated by
 * brackets.<br/>
 * Package private because LexerBuilder exists which must be used
 *
 * @author Eugen Fischer
 * @param <T> bounded type for lexer
 */
@ToString
@EqualsAndHashCode(callSuper = true)
class BracketLexer<T extends FormatterSupport> extends Lexer<T> {

    private static final long serialVersionUID = 6117181403355108849L;

    /**
     * Brackets defines start and end of one token
     *
     * @author Eugen Fischer
     */
    enum Brackets {
        /** squared brackets [ ] */
        SQUARED_BRACKTES('[', ']'),
        /** curly brackets { } */
        CURLY_BRACKETS('{', '}'),
        /** angle brackets < > */
        ANGLE_BRACKET('<', '>');

        final char leftBracket;

        final char rightBracket;

        Brackets(final char left, final char right) {
            leftBracket = left;
            rightBracket = right;
        }
    }

    private final Brackets brackets;

    /**
     * Constructor of BracketParser initialize his parse behavior.
     * Source provide information of "tokens" which he supports. Therefore
     * FormatterSupport.getSupportedPropertyNames() of the source will be used.
     * The template input should include Bracket separated attributes. Everything else caused
     * exception.
     *
     * @param source must nut be null
     * @param brackets as separators of attributes. must nut be null
     */
    BracketLexer(final T source, final Brackets brackets) {
        super(source);
        this.brackets = checkNotNull(brackets, "Brackets must not be null.");
    }

    @Override
    public List<Token> scan(final String input) {
        final List<Token> tokens = new ArrayList<>();

        if (!isNullOrEmpty(input)) {

            final List<String> chunksSplitByLeftBracket = splitByLeftBracket(input);
            final List<String> chunksSplitByRightBracket = splitByRightBracket(input);

            checkArgument(chunksSplitByLeftBracket.size() == chunksSplitByRightBracket.size(),
                    "pattern '" + input + "' is unbalanced");

            for (final String chunk : chunksSplitByRightBracket) {
                if (!isNullOrEmpty(chunk)) {
                    parseChunk(chunk, tokens);
                }
            }
        }

        return tokens;
    }

    private List<String> splitByLeftBracket(final String input) {
        return Lists.newArrayList(Splitter.on(this.brackets.leftBracket).split(input));
    }

    private List<String> splitByRightBracket(final String input) {
        return Lists.newArrayList(Splitter.on(this.brackets.rightBracket).split(input));
    }

    private void parseChunk(final String chunk, final List<Token> tokens) {
        final String cleaned = disposeStringToken(chunk, tokens);
        if (!isNullOrEmpty(cleaned)) {
            boolean tokenRecognized = false;

            final String token = getBestFittingToken(cleaned, getTokenList());
            if (null != token) {
                tokens.add(new ActionToken(cleaned, token));
                tokenRecognized = true;
            }
            if (!tokenRecognized) {
                throwUnsupportedTokenException(cleaned, getTokenList());
            }
        }
    }

    private String getBestFittingToken(final String cleanedChunk, final List<String> tokens) {
        Candidate mostFittingCandidate = new Candidate(cleanedChunk, null);
        for (final String token : tokens) {
            if (!isNullOrEmpty(token) && cleanedChunk.contains(token)) {
                final Candidate otherCandidate = new Candidate(cleanedChunk, token);
                if (!mostFittingCandidate.fitsMoreThan(otherCandidate)) {
                    mostFittingCandidate = otherCandidate;
                }
            }
        }
        return mostFittingCandidate.getTokenName();
    }

    private String disposeStringToken(final String chunk, final List<Token> tokens) {
        int startPoint = chunk.indexOf(this.brackets.leftBracket);
        if (startPoint > 0) {
            // string token before was found
            final String value = chunk.substring(0, startPoint);
            tokens.add(new StringToken(value));
        } else {
            // last string token found
            if (startPoint == -1) {
                startPoint = chunk.length() - 1;
                tokens.add(new StringToken(chunk));
            }
        }
        return chunk.substring(startPoint + 1);
    }

    private class Candidate {

        private static final int HUGE_NUMBER = 999999;

        private final String tokenName;

        private final int fittingIndex;

        public String getTokenName() {
            return this.tokenName;
        }

        public int getFittingIndex() {
            return this.fittingIndex;
        }

        public Candidate(final String cleanedChunk, final String tokenName) {
            if (null != tokenName) {
                this.tokenName = tokenName;
                int difference = cleanedChunk.compareTo(tokenName);
                if (0 > difference) {
                    difference = difference * -1;
                }
                this.fittingIndex = difference;
            } else {
                this.tokenName = null;
                this.fittingIndex = HUGE_NUMBER;
            }
        }

        public boolean fitsMoreThan(final Candidate otherCandidate) {
            return this.fittingIndex < otherCandidate.getFittingIndex();
        }
    }

}
