package de.cuioss.tools.string;

import static de.cuioss.tools.string.MoreStrings.isEmpty;
import static de.cuioss.tools.string.MoreStrings.nullToEmpty;
import static java.lang.Integer.valueOf;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.regex.Pattern;

import de.cuioss.tools.collect.MapBuilder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

/**
 * This class provide functionality to transform long text to several html
 * useful representation and encapsulate this as an object. It is implemented as
 * an value-object keeping the calculated text.
 *
 * @author Eugen Fischer
 */
@EqualsAndHashCode(of = { "source", "abridgedLength", "forceLengthBreak" })
@ToString(of = { "source", "abridgedLength", "forceLengthBreak" })
public class TextSplitter implements Serializable {

    /** serial Version UID */
    private static final long serialVersionUID = 6594890288982910944L;

    /**
     * Der Browser muss über Sollbruchstellen die Möglichkeit bekommen lange
     * Wortketten zu trennen/umzubrechen. Dafür gibt es zwei unsichtbare Zeichen,
     * die in den HTML code eingebaut werden können: "&amp;shy;" und "&amp;#8203;".
     * Der Unterschied zwischen beiden ist, dass das eine einfach ein Leerzeichen
     * ohne breite ist, welches beim Umbruch keine Spuren hinterlässt, das andere
     * fügt bei einem Umbruch einen Bindestrich hinzu. Eignet sich also zur
     * Silbentrennung.
     */
    private static final String ZERO_WIDTH_SPACE = "\u200B";

    private static final String TRADE_STR = "...";

    private static final int DEFAULT_FORCE_LENGTH_BREAK = 15;

    private static final int DEFAULT_ABRIDGED_LENGTH = 20;

    private static final Map<Pattern, String> REPLACEMENT_MAP = new MapBuilder<Pattern, String>()
            .put(Pattern.compile("#"), "#" + ZERO_WIDTH_SPACE).put(Pattern.compile("\\+"), "+" + ZERO_WIDTH_SPACE)
            .put(Pattern.compile("-"), "-" + ZERO_WIDTH_SPACE).put(Pattern.compile("_"), "_" + ZERO_WIDTH_SPACE)
            .put(Pattern.compile("\\."), "." + ZERO_WIDTH_SPACE).put(Pattern.compile("\\?"), "?" + ZERO_WIDTH_SPACE)
            .put(Pattern.compile("!"), "!" + ZERO_WIDTH_SPACE).put(Pattern.compile(":"), ":" + ZERO_WIDTH_SPACE)
            .put(Pattern.compile(","), "," + ZERO_WIDTH_SPACE).put(Pattern.compile(";"), ";" + ZERO_WIDTH_SPACE)
            .toImmutableMap();

    private final String source;

    @Getter(lazy = true)
    private final String abridgedText = initAbridged();

    @Getter
    private boolean abridged = false;

    @Getter(lazy = true)
    private final String textWithEnforcedLineBreaks = initTextWithLineBreaks();

    @Setter
    private Integer forceLengthBreak = null;

    @Setter
    private Integer abridgedLength = null;

    /**
     * Construct TextSplitter.
     *
     * @param longString source text which will be processed
     */
    public TextSplitter(final String longString) {
        source = nullToEmpty(longString);
    }

    /**
     * Alternative Constructor
     *
     * @param source                target text
     * @param forceLengthBreakCount count of characters when a text break will
     *                              forced
     * @param abridgedLengthCount   count of characters
     */
    public TextSplitter(final String source, final int forceLengthBreakCount, final int abridgedLengthCount) {

        this.source = source;
        forceLengthBreak = valueOf(forceLengthBreakCount);
        abridgedLength = valueOf(abridgedLengthCount);
    }

    private int getForceLengthBreak() {
        if (null == forceLengthBreak) {
            return DEFAULT_FORCE_LENGTH_BREAK;
        }
        return forceLengthBreak;
    }

    private int getAbridgedLength() {
        if (null == abridgedLength) {
            return DEFAULT_ABRIDGED_LENGTH;
        }
        return abridgedLength;
    }

    private String initAbridged() {
        var result = "";

        if (!isEmpty(source)) {

            final var sourceSplitted = getSourceSplitted();

            if (sourceSplitted.size() == 1) {
                result = abridgeComputerProducedText();
            } else {
                result = abridgeHumanProducedText(sourceSplitted);
            }
        }

        abridged = endsWith(result, TRADE_STR);

        return result.trim();
    }

    private static boolean endsWith(final String str, final String suffix) {
        return str.trim().endsWith(suffix);
    }

    /**
     * @return abridged text
     */
    private String abridgeComputerProducedText() {
        final var maxLength = getAbridgedLength() - (TRADE_STR.length() + 1);
        if (source.length() > maxLength) {
            return source.substring(0, maxLength) + " ...";
        }
        return source;
    }

    /**
     * @param sourceSplitted
     * @return abridged text
     */
    private String abridgeHumanProducedText(final List<String> sourceSplitted) {
        final var maxLength = getAbridgedLength() - TRADE_STR.length();
        final var builder = new StringBuilder();
        var count = 0;
        for (final String part : sourceSplitted) {
            count = count + part.length();
            if (count >= maxLength) {
                builder.append(TRADE_STR);
                break;
            }

            builder.append(part).append(" ");

            count = count + 1;
        }
        return builder.toString();
    }

    private String initTextWithLineBreaks() {

        var result = "";

        if (!isEmpty(source)) {
            final var sourceSplitted = getSourceSplitted();
            if (sourceSplitted.size() == 1) {
                result = forceLineBreakForComputerProducedText(source);
            } else {
                result = forceLineBreakForHumanProducedText(sourceSplitted);
            }
        }

        return result.trim();
    }

    private String forceLineBreakForHumanProducedText(final List<String> sourceSplitted) {
        final var builder = new StringBuilder();
        for (final String text : sourceSplitted) {
            builder.append(forceLineBreakForComputerProducedText(text)).append(" ");
        }
        return builder.toString();
    }

    /**
     * Try to separate text target on native text breaks. If this is not enough use
     * brute-force on max allowed length.
     *
     * @param text target which will be analyzed
     * @return
     */
    private String forceLineBreakForComputerProducedText(final String text) {

        // try to separate on native text breaks
        var clean = text;
        for (final Entry<Pattern, String> entry : REPLACEMENT_MAP.entrySet()) {
            final var matcher = entry.getKey().matcher(clean);
            clean = matcher.replaceAll(entry.getValue());
        }

        final var splittedByZeroWidthSpace = getSplittedByZeroWidthSpace(clean);
        final List<String> lengthTrimed = new ArrayList<>();

        for (final String item : splittedByZeroWidthSpace) {
            lengthTrimed.add(bruteForceSplit(item));
        }

        return Joiner.on(ZERO_WIDTH_SPACE).join(lengthTrimed);
    }

    /**
     * Verify if very long text still exists and execute brute-force dissipation
     *
     * @param text target
     * @return fragmented text if length doesn't fit to force length break
     */
    private String bruteForceSplit(final String text) {
        final var maxLength = getForceLengthBreak();
        if (!isEmpty(text)) {
            final var builder = new StringBuilder();
            var tmp = text;
            while (tmp.length() > maxLength) {
                builder.append(tmp, 0, maxLength).append(ZERO_WIDTH_SPACE);
                tmp = tmp.substring(maxLength);
            }
            if (!tmp.isEmpty()) {
                builder.append(tmp);
            }
            return builder.toString();
        }
        return text;
    }

    private static List<String> getSplittedByZeroWidthSpace(final String value) {
        return Splitter.on(ZERO_WIDTH_SPACE).splitToList(value);
    }

    private List<String> getSourceSplitted() {
        return Splitter.on(" ").splitToList(source);
    }
}
