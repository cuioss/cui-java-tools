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
package de.cuioss.tools.string;

import de.cuioss.tools.collect.MapBuilder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.io.Serial;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.regex.Pattern;

import static de.cuioss.tools.string.MoreStrings.isEmpty;
import static de.cuioss.tools.string.MoreStrings.nullToEmpty;
import static java.lang.Integer.valueOf;

/**
 * Utility class for transforming long text into HTML-friendly representations.
 * This class provides functionality to:
 * <ul>
 *   <li>Abridge long text with ellipsis (...)</li>
 *   <li>Insert zero-width spaces for better line breaking</li>
 *   <li>Handle both computer-generated and human-written text differently</li>
 *   <li>Enforce line breaks at specific intervals</li>
 * </ul>
 *
 * <h2>Key Features</h2>
 * <ul>
 *   <li>Immutable value object design</li>
 *   <li>Configurable length limits for abridging and line breaks</li>
 *   <li>Smart handling of punctuation for line breaks</li>
 *   <li>Preservation of existing word boundaries</li>
 * </ul>
 *
 * <h2>Usage Examples</h2>
 * <pre>
 * // Basic usage with defaults
 * TextSplitter splitter1 = new TextSplitter("This is a very long text that needs splitting");
 * String abridged = splitter1.getAbridgedText();          // "This is a very lon..."
 * String withBreaks = splitter1.getTextWithEnforcedLineBreaks();  // Adds zero-width spaces
 *
 * // Custom configuration
 * TextSplitter splitter2 = new TextSplitter("Long.Technical-ID#12345", 5, 10);
 * // Results in: "Long.⁠Technical-⁠ID#⁠12345" (⁠ represents zero-width space)
 * </pre>
 *
 * @author Eugen Fischer
 */
@EqualsAndHashCode(of = {"source", "abridgedLength", "forceLengthBreak"})
@ToString(of = {"source", "abridgedLength", "forceLengthBreak"})
public class TextSplitter implements Serializable {

    @Serial
    private static final long serialVersionUID = 6594890288982910944L;

    /**
     * Zero-width space character (U+200B) used for providing line break opportunities
     * in HTML without affecting the visual appearance. This character allows the browser
     * to break long words at appropriate points without adding visible spaces or hyphens.
     */
    private static final String ZERO_WIDTH_SPACE = "\u200B";

    /** Ellipsis string used for indicating truncated text */
    private static final String TRADE_STR = "...";

    /** Default number of characters before forcing a line break */
    private static final int DEFAULT_FORCE_LENGTH_BREAK = 15;

    /** Default maximum length before text is abridged */
    private static final int DEFAULT_ABRIDGED_LENGTH = 20;

    /**
     * Map of patterns to their replacements with zero-width spaces.
     * Each pattern represents a character that should be followed by a zero-width space
     * to provide additional line break opportunities.
     */
    private static final Map<Pattern, String> REPLACEMENT_MAP = new MapBuilder<Pattern, String>()
            .put(Pattern.compile("#"), "#" + ZERO_WIDTH_SPACE)
            .put(Pattern.compile("\\+"), "+" + ZERO_WIDTH_SPACE)
            .put(Pattern.compile("-"), "-" + ZERO_WIDTH_SPACE)
            .put(Pattern.compile("_"), "_" + ZERO_WIDTH_SPACE)
            .put(Pattern.compile("\\."), "." + ZERO_WIDTH_SPACE)
            .put(Pattern.compile("\\?"), "?" + ZERO_WIDTH_SPACE)
            .put(Pattern.compile("!"), "!" + ZERO_WIDTH_SPACE)
            .put(Pattern.compile(":"), ":" + ZERO_WIDTH_SPACE)
            .put(Pattern.compile(","), "," + ZERO_WIDTH_SPACE)
            .put(Pattern.compile(";"), ";" + ZERO_WIDTH_SPACE)
            .toImmutableMap();

    /** The original source text to be processed */
    private final String source;

    /**
     * Lazily initialized abridged version of the source text.
     * Will be truncated with ellipsis if longer than the configured length.
     */
    @Getter(lazy = true)
    private final String abridgedText = initAbridged();

    /**
     * Indicates whether the text was actually abridged.
     * True if the text ends with ellipsis, false otherwise.
     */
    @Getter
    private boolean abridged = false;

    /**
     * Lazily initialized version of the text with enforced line breaks.
     * Contains zero-width spaces at appropriate break points.
     */
    @Getter(lazy = true)
    private final String textWithEnforcedLineBreaks = initTextWithLineBreaks();

    /**
     * Maximum length of text segments before forcing a line break.
     * If null, uses {@link #DEFAULT_FORCE_LENGTH_BREAK}.
     */
    @Setter
    private Integer forceLengthBreak = null;

    /**
     * Maximum length of text before abridging with ellipsis.
     * If null, uses {@link #DEFAULT_ABRIDGED_LENGTH}.
     */
    @Setter
    private Integer abridgedLength = null;

    /**
     * Creates a new TextSplitter with default settings.
     *
     * @param longString source text to be processed, will be converted to empty string if null
     */
    public TextSplitter(final String longString) {
        source = nullToEmpty(longString);
    }

    /**
     * Creates a new TextSplitter with custom length settings.
     *
     * @param source text to be processed
     * @param forceLengthBreakCount maximum length before forcing line breaks
     * @param abridgedLengthCount maximum length before abridging with ellipsis
     */
    public TextSplitter(final String source, final int forceLengthBreakCount, final int abridgedLengthCount) {
        this.source = source;
        forceLengthBreak = valueOf(forceLengthBreakCount);
        abridgedLength = valueOf(abridgedLengthCount);
    }

    private int getForceLengthBreak() {
        return forceLengthBreak != null ? forceLengthBreak : DEFAULT_FORCE_LENGTH_BREAK;
    }

    private int getAbridgedLength() {
        return abridgedLength != null ? abridgedLength : DEFAULT_ABRIDGED_LENGTH;
    }

    private String initAbridged() {
        String result = "";

        if (!isEmpty(source)) {
            final List<String> sourceSplitted = getSourceSplit();
            result = sourceSplitted.size() == 1
                    ? abridgeComputerProducedText()
                    : abridgeHumanProducedText(sourceSplitted);
        }

        abridged = endsWith(result, TRADE_STR);
        return result.trim();
    }

    private static boolean endsWith(final String str, final String suffix) {
        return str.trim().endsWith(suffix);
    }

    /**
     * Abridges computer-produced text (single word/token) by truncating at the maximum length
     * and adding ellipsis if necessary.
     *
     * @return the abridged text, or original if no abridgement needed
     */
    private String abridgeComputerProducedText() {
        final int maxLength = getAbridgedLength() - (TRADE_STR.length() + 1);
        return source.length() > maxLength
                ? source.substring(0, maxLength) + " " + TRADE_STR
                : source;
    }

    /**
     * Abridges human-produced text (multiple words) by keeping as many complete words
     * as possible within the length limit.
     *
     * @param sourceSplit list of words from the source text
     * @return the abridged text with ellipsis if truncated
     */
    private String abridgeHumanProducedText(final List<String> sourceSplit) {
        final int maxLength = getAbridgedLength() - TRADE_STR.length();
        final StringBuilder builder = new StringBuilder();
        int count = 0;

        for (final String part : sourceSplit) {
            count += part.length();
            if (count >= maxLength) {
                builder.append(TRADE_STR);
                break;
            }
            builder.append(part).append(" ");
            count++; // Account for space
        }
        return builder.toString();
    }

    private String initTextWithLineBreaks() {
        if (isEmpty(source)) {
            return "";
        }

        final List<String> sourceSplit = getSourceSplit();
        return (sourceSplit.size() == 1
                ? forceLineBreakForComputerProducedText(source)
                : forceLineBreakForHumanProducedText(sourceSplit))
                .trim();
    }

    /**
     * Processes human-produced text by applying line break rules to each word separately.
     *
     * @param sourceSplit list of words from the source text
     * @return processed text with appropriate line break opportunities
     */
    private String forceLineBreakForHumanProducedText(final List<String> sourceSplit) {
        final StringBuilder builder = new StringBuilder();
        for (final String text : sourceSplit) {
            builder.append(forceLineBreakForComputerProducedText(text)).append(" ");
        }
        return builder.toString();
    }

    /**
     * Processes computer-produced text by:
     * 1. Adding zero-width spaces after punctuation
     * 2. Breaking long segments that exceed the maximum length
     *
     * @param text text to be processed
     * @return processed text with appropriate line break opportunities
     */
    private String forceLineBreakForComputerProducedText(final String text) {
        // Add zero-width spaces after punctuation
        String clean = text;
        for (final Entry<Pattern, String> entry : REPLACEMENT_MAP.entrySet()) {
            clean = entry.getKey().matcher(clean).replaceAll(entry.getValue());
        }

        // Process each segment
        final List<String> splitByZWSP = getSplitByZWSP(clean);
        final List<String> lengthTrimmed = new ArrayList<>();

        for (final String item : splitByZWSP) {
            lengthTrimmed.add(bruteForceSplit(item));
        }

        return Joiner.on(ZERO_WIDTH_SPACE).join(lengthTrimmed);
    }

    /**
     * Breaks text into smaller segments if it exceeds the maximum length.
     * This is a last resort for very long text without natural break points.
     *
     * @param text text to be split
     * @return text with forced breaks at maximum length intervals
     */
    private String bruteForceSplit(final String text) {
        if (isEmpty(text)) {
            return text;
        }

        final int maxLength = getForceLengthBreak();
        if (text.length() <= maxLength) {
            return text;
        }

        final StringBuilder builder = new StringBuilder();
        String remaining = text;

        while (remaining.length() > maxLength) {
            builder.append(remaining, 0, maxLength)
                    .append(ZERO_WIDTH_SPACE);
            remaining = remaining.substring(maxLength);
        }

        if (!remaining.isEmpty()) {
            builder.append(remaining);
        }

        return builder.toString();
    }

    private static List<String> getSplitByZWSP(final String value) {
        return Splitter.on(Pattern.compile(Pattern.quote(ZERO_WIDTH_SPACE))).splitToList(value);
    }

    private List<String> getSourceSplit() {
        return Splitter.on(Pattern.compile("\\s+")).splitToList(source);
    }
}
