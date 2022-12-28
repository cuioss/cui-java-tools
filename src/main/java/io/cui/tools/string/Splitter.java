package io.cui.tools.string;

import static io.cui.tools.base.Preconditions.checkArgument;
import static io.cui.tools.string.MoreStrings.isEmpty;
import static io.cui.tools.string.MoreStrings.requireNotEmpty;
import static java.util.Objects.requireNonNull;

import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

import io.cui.tools.collect.CollectionBuilder;
import io.cui.tools.logging.CuiLogger;
import lombok.AccessLevel;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * Derived from Googles Splitter.
 * <p>
 * It uses internally the {@link String#split(String)} implementation
 * of java and provides a guava like wrapper. This results in an implicit splitting of the whole
 * String compared to the lazy / deferred splitting of guava. It focuses and RegEx-based splitting
 * and omits the fixedLength and Map based variants.
 * </p>
 * <h2>Migrating from Guava</h2>
 * <p>
 * In order to migrate for most case you only need to replace the package name on the import. A
 * major different is that the split method provided is {@link #splitToList(String)}, the variant
 * split() is replaced by it completely.
 * </p>
 * <h2>Changes to Guavas-Splitter</h2>
 * <p>
 * It is quite similar to the guava variant but behaves a little
 * different in certain details, especially in the context of {@link Splitter#limit(int)} and
 * {@link Splitter#trimResults()}, {@link Splitter#omitEmptyStrings()}.
 * While guavas version will filter the limit elements after the
 * application of omit / trim, this version will do it the other way round, resulting in a different
 * result compared to the guava version.
 * </p>
 *
 * @author Oliver Wolff
 *
 */
@RequiredArgsConstructor(access = AccessLevel.MODULE)
public final class Splitter {

    private static final CuiLogger log = new CuiLogger(Splitter.class);

    @NonNull
    private final SplitterConfig splitterConfig;

    /**
     * Returns a splitter that uses the given fixed string as a separator. For example, {@code
     * Splitter.on(", ").split("foo, bar,baz")} returns an iterable containing {@code ["foo",
     * "bar,baz"]}.
     *
     * @param separator the literal, nonempty string to recognize as a separator
     *
     * @return a splitter, with default settings, that recognizes that separator
     */
    public static Splitter on(final String separator) {
        requireNotEmpty(separator);
        return new Splitter(SplitterConfig.builder().separator(separator).build());
    }

    /**
     * Returns a splitter that uses the given fixed string as a separator. For example, {@code
     * Splitter.on(", ").split("foo, bar,baz")} returns an iterable containing {@code ["foo",
     * "bar,baz"]}.
     *
     * @param separator the literal, nonempty string to recognize as a separator
     *
     * @return a splitter, with default settings, that recognizes that separator
     */
    public static Splitter on(final char separator) {
        requireNonNull(separator);
        return new Splitter(SplitterConfig.builder().separator(String.valueOf(separator)).build());
    }

    /**
     * Returns a splitter that behaves equivalently to {@code this} splitter, but automatically
     * omits empty strings from the results. For example, {@code
     * Splitter.on(',').omitEmptyStrings().split(",a,,,b,c,,")} returns an iterable containing only
     * {@code ["a", "b", "c"]}.
     *
     * <p>
     * If either {@code trimResults} option is also specified when creating a splitter, that
     * splitter always trims results first before checking for emptiness. So, for example, {@code
     * Splitter.on(':').omitEmptyStrings().trimResults().split(": : : ")} returns an empty iterable.
     * <p>
     *
     * @return a splitter with the desired configuration
     */
    public Splitter omitEmptyStrings() {
        return new Splitter(splitterConfig.copy().omitEmptyStrings(true).build());
    }

    /**
     * Usually the separator will be pre-processed before being passed to
     * {@link String#split(String)}. This is needed to mask special characters that will harm
     * {@link Pattern#compile(String)}. If you want to disable this behavior and take care for your
     * self you can change this method by calling this method.
     *
     * @return a splitter with the desired configuration
     */
    public Splitter doNotModifySeparatorString() {
        return new Splitter(splitterConfig.copy().doNotModifySeparatorString(true).build());
    }

    /**
     * Returns a splitter that behaves equivalently to {@code this} splitter, but automatically
     * removes leading and trailing whitespace from each
     * returned substring. For example,
     * {@code Splitter.on(',').trimResults().split(" a, b ,c ")} returns an iterable containing
     * {@code ["a", "b", "c"]}.
     *
     * @return a splitter with the desired configuration
     */
    public Splitter trimResults() {
        return new Splitter(splitterConfig.copy().trimResults(true).build());
    }

    /**
     * Returns a splitter that behaves equivalently to {@code this} splitter but stops splitting
     * after it reaches the limit. The limit defines the maximum number of items returned by the
     * iterator, or the maximum size of the list returned by {@link #splitToList}.
     *
     * <p>
     * For example, {@code Splitter.on(',').limit(3).split("a,b,c,d")} returns an iterable
     * containing {@code ["a", "b", "c,d"]}. When omitting empty strings, the omitted strings do not
     * count. Hence, {@code Splitter.on(',').limit(3).omitEmptyStrings().split("a,,,b,,,c,d")}
     * returns an iterable containing {@code ["a", "b", "c,d"}. When trim is requested, all entries
     * are trimmed, including the last. Hence
     * {@code Splitter.on(',').limit(3).trimResults().split(" a , b
     * , c , d ")} results in {@code ["a", "b", "c , d"]}.
     *
     * @param maxItems the maximum number of items returned
     * @return a splitter with the desired configuration
     */
    public Splitter limit(int maxItems) {
        checkArgument(maxItems > 0, "must be greater than zero: %s");
        return new Splitter(splitterConfig.copy().maxItems(maxItems).build());
    }

    /**
     * Splits {@code sequence} into string components and returns them as an immutable list.
     *
     * @param sequence the sequence of characters to split
     *
     * @return an immutable list of the segments split from the parameter
     */
    public List<String> splitToList(String sequence) {
        log.trace("Splitting String {} with configuration {}", sequence, splitterConfig);
        if (isEmpty(sequence)) {
            return Collections.emptyList();
        }
        String[] splitted =
            sequence.split(handleSplitCharacter(splitterConfig.getSeparator()), splitterConfig.getMaxItems());
        if (null == splitted || 0 == splitted.length) {
            log.trace("No content to be returned for input {} and configuration {}", sequence, splitterConfig);
            return Collections.emptyList();
        }
        CollectionBuilder<String> builder = new CollectionBuilder<>();

        for (String element : splitted) {
            addIfApplicable(builder, element);
        }
        return builder.toImmutableList();
    }

    private String handleSplitCharacter(String separator) {
        if (splitterConfig.isDoNotModifySeparatorString()) {
            return separator;
        }
        return Pattern.quote(separator);
    }

    private void addIfApplicable(CollectionBuilder<String> builder, String element) {
        if (null == element) {
            return;
        }
        String toDo = element;
        if (splitterConfig.isTrimResults()) {
            toDo = toDo.trim();
        }
        if (!splitterConfig.isOmitEmptyStrings()) {
            builder.add(toDo);
            return;
        }
        if (!toDo.isEmpty()) { // Omit empty strings
            builder.add(toDo);
        }
    }
}
