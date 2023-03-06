package de.cuioss.tools.string;

import static de.cuioss.tools.collect.CollectionLiterals.mutableList;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledForJreRange;
import org.junit.jupiter.api.condition.JRE;
import org.opentest4j.AssertionFailedError;

/**
 * Initially taken from
 * https://github.com/google/guava/blob/master/guava-tests/test/com/google/common/base/JoinerTest.java
 */
class JoinerTest {

    private static final Joiner J = Joiner.on("-");

    // <Integer> needed to prevent warning :(
    private static final Iterable<Integer> ITERABLE_EMPTY = List.of();
    private static final Iterable<Integer> ITERABLE_1 = List.of(1);
    private static final Iterable<Integer> ITERABLE_12 = Arrays.asList(1, 2);
    private static final Iterable<Integer> ITERABLE_123 = Arrays.asList(1, 2, 3);
    private static final Iterable<Integer> ITERABLE_NULL = Collections.singletonList((Integer) null);
    private static final Iterable<Integer> ITERABLE_NULL_NULL = Arrays.asList(null, null);
    private static final Iterable<Integer> ITERABLE_NULL_1 = Arrays.asList(null, 1);
    private static final Iterable<Integer> ITERABLE_1_NULL = Arrays.asList(1, null);
    private static final Iterable<Integer> ITERABLE_1_NULL_2 = Arrays.asList(1, null, 2);
    private static final Iterable<Integer> ITERABLE_FOUR_NULLS =
        Arrays.asList(null, null, null, null);

    @Test
    void testOnCharOverride() {
        final var onChar = Joiner.on('-');
        assertNoOutput(onChar, ITERABLE_EMPTY);
        assertResult(onChar, ITERABLE_1, "1");
        assertResult(onChar, ITERABLE_12, "1-2");
        assertResult(onChar, ITERABLE_123, "1-2-3");
    }

    @Test
    void testSkipNulls() {
        final var skipNulls = J.skipNulls();
        assertNoOutput(skipNulls, ITERABLE_EMPTY);
        assertNoOutput(skipNulls, ITERABLE_NULL);
        assertNoOutput(skipNulls, ITERABLE_NULL_NULL);
        assertNoOutput(skipNulls, ITERABLE_FOUR_NULLS);
        assertResult(skipNulls, ITERABLE_1, "1");
        assertResult(skipNulls, ITERABLE_12, "1-2");
        assertResult(skipNulls, ITERABLE_123, "1-2-3");
        assertResult(skipNulls, ITERABLE_NULL_1, "1");
        assertResult(skipNulls, ITERABLE_1_NULL, "1");
        assertResult(skipNulls, ITERABLE_1_NULL_2, "1-2");
    }

    @Test
    void testSkipEmptyStrings() {
        final var skipEmptyStrings = J.skipEmptyStrings().skipNulls();
        assertNoOutput(skipEmptyStrings, ITERABLE_EMPTY);
        assertNoOutput(skipEmptyStrings, ITERABLE_NULL);
        assertNoOutput(skipEmptyStrings, ITERABLE_NULL_NULL);
        assertNoOutput(skipEmptyStrings, ITERABLE_FOUR_NULLS);
        assertResult(skipEmptyStrings, mutableList("1"), "1");
        assertResult(skipEmptyStrings, mutableList("1", ""), "1");
        assertResult(skipEmptyStrings, mutableList("1", "2"), "1-2");
        assertResult(skipEmptyStrings, mutableList("1", "2", ""), "1-2");
        assertResult(skipEmptyStrings, mutableList("", "1", "2", ""), "1-2");
        assertResult(skipEmptyStrings, ITERABLE_123, "1-2-3");
        assertResult(skipEmptyStrings, ITERABLE_NULL_1, "1");
        assertResult(skipEmptyStrings, ITERABLE_1_NULL, "1");
        assertResult(skipEmptyStrings, ITERABLE_1_NULL_2, "1-2");
    }

    @Test
    void testSkipBlankStrings() {
        final var skipEmptyStrings = J.skipBlankStrings().skipNulls();
        assertNoOutput(skipEmptyStrings, ITERABLE_EMPTY);
        assertNoOutput(skipEmptyStrings, ITERABLE_NULL);
        assertNoOutput(skipEmptyStrings, ITERABLE_NULL_NULL);
        assertNoOutput(skipEmptyStrings, ITERABLE_FOUR_NULLS);
        assertResult(skipEmptyStrings, mutableList("1"), "1");
        assertResult(skipEmptyStrings, mutableList("1", "  "), "1");
        assertResult(skipEmptyStrings, mutableList("1", "2"), "1-2");
        assertResult(skipEmptyStrings, mutableList("1", "2", "  "), "1-2");
        assertResult(skipEmptyStrings, mutableList("", "1", "2", "   "), "1-2");
        assertResult(skipEmptyStrings, ITERABLE_123, "1-2-3");
        assertResult(skipEmptyStrings, ITERABLE_NULL_1, "1");
        assertResult(skipEmptyStrings, ITERABLE_1_NULL, "1");
        assertResult(skipEmptyStrings, ITERABLE_1_NULL_2, "1-2");
    }

    @Test
    void testUseForNull() {
        final var zeroForNull = J.useForNull("0");
        assertNoOutput(zeroForNull, ITERABLE_EMPTY);
        assertResult(zeroForNull, ITERABLE_1, "1");
        assertResult(zeroForNull, ITERABLE_12, "1-2");
        assertResult(zeroForNull, ITERABLE_123, "1-2-3");
        assertResult(zeroForNull, ITERABLE_NULL, "0");
        assertResult(zeroForNull, ITERABLE_NULL_NULL, "0-0");
        assertResult(zeroForNull, ITERABLE_NULL_1, "0-1");
        assertResult(zeroForNull, ITERABLE_1_NULL, "1-0");
        assertResult(zeroForNull, ITERABLE_1_NULL_2, "1-0-2");
        assertResult(zeroForNull, ITERABLE_FOUR_NULLS, "0-0-0-0");
    }

    private static void assertNoOutput(final Joiner joiner, final Iterable<?> set) {
        assertEquals("", joiner.join(set));
    }

    private static void assertResult(final Joiner joiner, final Iterable<?> parts, final String expected) {
        assertEquals(expected, joiner.join(parts));
        assertEquals(expected, joiner.join(parts.iterator()));
    }

    private static class DontStringMeBro implements CharSequence {

        @Override
        public int length() {
            return 3;
        }

        @Override
        public char charAt(final int index) {
            return "foo".charAt(index);
        }

        @Override
        public CharSequence subSequence(final int start, final int end) {
            return "foo".subSequence(start, end);
        }

        @Override
        public String toString() {
            throw new AssertionFailedError("shouldn't be invoked");
        }
    }

    @Test
    // FIXME this is not working in JAVA 11 due to a changed String#join method
    // FIXME owolff: Hm I'm not sure whether the old behavior is a problem at all. The main
    // difference is not calling the toString method CharSequence. This code is taken directly from
    // guava, and may be a problem there, but I do not think it is a problem within our JRE based
    // approach
    @DisabledForJreRange(min = JRE.JAVA_11)
    void testDontConvertCharSequenceToString() {
        assertEquals("foo,foo", Joiner.on(",").join(new DontStringMeBro(), new DontStringMeBro()));
        assertEquals(
                "foo,bar,foo",
                Joiner.on(",").useForNull("bar").join(new DontStringMeBro(), null, new DontStringMeBro()));
    }

}