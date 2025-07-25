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
package de.cuioss.tools.formatting.template.lexer;

import de.cuioss.tools.formatting.template.FormatterSupport;
import de.cuioss.tools.formatting.template.token.ActionToken;
import de.cuioss.tools.formatting.template.token.StringToken;
import de.cuioss.tools.formatting.template.token.Token;
import de.cuioss.tools.string.MoreStrings;
import de.cuioss.tools.string.Splitter;
import lombok.EqualsAndHashCode;
import lombok.ToString;

import java.io.Serial;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import static de.cuioss.tools.base.Preconditions.checkArgument;
import static de.cuioss.tools.string.MoreStrings.isEmpty;
import static java.util.Objects.requireNonNull;

/**
 * Simple lexer which supports parsing of template pattern where attributes are
 * separated by brackets. Package private because LexerBuilder exists which must
 * be used
 *
 * @param <T> bounded type for lexer
 *
 * @author Eugen Fischer
 */
@ToString
@EqualsAndHashCode(callSuper = true)
class BracketLexer<T extends FormatterSupport> extends Lexer<T> {

    @Serial
    private static final long serialVersionUID = 6117181403355108849L;

    /**
     * Brackets defines start and end of one token
     *
     * @author Eugen Fischer
     */
    enum Brackets {

        /**
         * squared brackets [ ]
         */
        SQUARED_BRACKETS('[', ']'),
        /**
         * curly brackets { }
         */
        CURLY_BRACKETS('{', '}'),
        /**
         * angle brackets < >
         */
        ANGLE_BRACKET('<', '>');

        final char leftBracket;

        final char rightBracket;

        Brackets(final char left, final char right) {
            leftBracket = left;
            rightBracket = right;
        }

        List<String> splitByLeftBracket(final String input) {
            return Splitter.on(leftBracket).omitEmptyStrings().splitToList(input);
        }

        List<String> splitByRightBracket(final String input) {
            return Splitter.on(rightBracket).omitEmptyStrings().splitToList(input);
        }

        @Override
        public String toString() {
            return "BracketLexer for " + leftBracket + rightBracket;
        }
    }

    private static final Pattern SPACE_CLEANER_PATTERN = Pattern.compile("\\,");

    private final Brackets brackets;

    private final boolean strict;

    /**
     * Constructor of BracketParser initialize its parse behavior. Source provide
     * information of "tokens" which he supports. Therefore,
     * FormatterSupport.getSupportedPropertyNames() of the source will be used. The
     * template input should include Bracket separated attributes. Everything else
     * caused exception.
     *
     * @param source   must not be null
     * @param brackets as separators of attributes. must nut be null
     */
    BracketLexer(final T source, final Brackets brackets) {
        this(source, brackets, false);
    }

    /**
     * Constructor of BracketParser initialize its parse behavior. Source provide
     * information of "tokens" which he supports. Therefore,
     * FormatterSupport.getSupportedPropertyNames() of the source will be used. The
     * template input should include Bracket separated attributes. Everything else
     * caused exception.
     *
     * @param source   must not be null
     * @param brackets as separators of attributes. must nut be null
     * @param strict   use strict mode for pattern matching (only match exact name)
     *                 instead of best fitting
     */
    BracketLexer(final T source, final Brackets brackets, final boolean strict) {
        super(source);
        this.brackets = requireNonNull(brackets, "Brackets must not be null.");
        this.strict = strict;
    }

    @Override
    public List<Token> scan(final String input) {
        final List<Token> tokens = new ArrayList<>();

        if (!isEmpty(input)) {

            final var chunksSplitByLeftBracket = brackets.splitByLeftBracket(input);
            final var chunksSplitByRightBracket = brackets.splitByRightBracket(input);
            var leftBracketCount = MoreStrings.countMatches(input, String.valueOf(brackets.leftBracket));
            var rightBracketCount = MoreStrings.countMatches(input, String.valueOf(brackets.rightBracket));
            var chunkCountEven = chunksSplitByLeftBracket.size() == chunksSplitByRightBracket.size();
            var bracketCountEven = leftBracketCount == rightBracketCount;
            // Assumption: Static elements are implicitly filtered
            checkArgument(chunkCountEven && bracketCountEven,
                    "pattern '%s' is unbalanced for %s, left-hand:%s, right-hand:%s", input, brackets,
                    chunksSplitByLeftBracket, chunksSplitByRightBracket);

            for (final String chunk : chunksSplitByRightBracket) {
                if (!isEmpty(chunk)) {
                    parseChunk(chunk, tokens);
                }
            }
        }

        return tokens;
    }

    private void parseChunk(final String chunk, final List<Token> tokens) {
        final var cleaned = disposeStringToken(chunk, tokens);
        if (!isEmpty(cleaned)) {
            var tokenRecognized = false;

            final String token;
            if (!strict) {
                token = getBestFittingToken(cleaned, getTokenList());
            } else {
                var spaceCleaned = SPACE_CLEANER_PATTERN.matcher(cleaned).replaceAll("").trim();
                if (getTokenList().contains(spaceCleaned)) {
                    token = spaceCleaned;
                } else {
                    token = null;
                }
            }
            if (null != token) {
                tokens.add(new ActionToken(cleaned, token));
                tokenRecognized = true;
            }
            if (!tokenRecognized) {
                throwUnsupportedTokenException(cleaned, getTokenList());
            }
        }
    }

    private static String getBestFittingToken(final String cleanedChunk, final List<String> tokens) {
        var mostFittingCandidate = new Candidate(cleanedChunk, null);
        for (final String token : tokens) {
            if (!isEmpty(token) && cleanedChunk.contains(token)) {
                final var otherCandidate = new Candidate(cleanedChunk, token);
                if (!mostFittingCandidate.fitsMoreThan(otherCandidate)) {
                    mostFittingCandidate = otherCandidate;
                }
            }
        }
        return mostFittingCandidate.getTokenName();
    }

    private String disposeStringToken(final String chunk, final List<Token> tokens) {
        var startPoint = chunk.indexOf(brackets.leftBracket);
        if (startPoint > 0) {
            // string token before was found
            final var value = chunk.substring(0, startPoint);
            tokens.add(new StringToken(value));
        } else // last string token found
            if (startPoint == -1) {
                startPoint = chunk.length() - 1;
                tokens.add(new StringToken(chunk));
            }
        return chunk.substring(startPoint + 1);
    }

    private static class Candidate {

        private static final int HUGE_NUMBER = 999999;

        private final String tokenName;

        private final int fittingIndex;

        public String getTokenName() {
            return tokenName;
        }

        public int getFittingIndex() {
            return fittingIndex;
        }

        public Candidate(final String cleanedChunk, final String tokenName) {
            if (null != tokenName) {
                this.tokenName = tokenName;
                var difference = cleanedChunk.compareTo(tokenName);
                if (0 > difference) {
                    difference = difference * -1;
                }
                fittingIndex = difference;
            } else {
                this.tokenName = null;
                fittingIndex = HUGE_NUMBER;
            }
        }

        public boolean fitsMoreThan(final Candidate otherCandidate) {
            return fittingIndex < otherCandidate.getFittingIndex();
        }
    }

}
