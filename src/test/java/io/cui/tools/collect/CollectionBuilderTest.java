package io.cui.tools.collect;

import static io.cui.tools.collect.CollectionLiterals.immutableList;
import static io.cui.tools.collect.CollectionLiterals.mutableList;
import static io.cui.tools.collect.CollectionLiterals.mutableSortedSet;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;

class CollectionBuilderTest {

    @Test
    void shouldHandleAddMethods() {
        final var builder = new CollectionBuilder<String>();
        builder.add("1");
        assertEquals(1, builder.size());
        builder.add("2", "3");
        assertEquals(3, builder.size());
        builder.add(Arrays.asList("4", "5"));
        assertEquals(5, builder.size());
        builder.add(Arrays.asList("6", "7").stream());
        assertEquals(7, builder.size());
        builder.add((Iterable<String>) Arrays.asList("8", "9"));
        assertEquals(9, builder.size());
        builder.add(Optional.of("10"));
        assertEquals(10, builder.size());
        builder.add(Optional.empty());
        assertEquals(10, builder.size());

        builder.add((String[]) null);
        assertEquals(10, builder.size());
    }

    @Test
    void shouldHandleAddIfPresentMethods() {
        final var builder = new CollectionBuilder<String>().addNullValues(true);
        builder.add("1");
        assertEquals(1, builder.size());
        builder.add(new String[] { null });
        assertEquals(2, builder.size());
        builder.add("2", "3");
        assertEquals(4, builder.size());
        builder.add(new String[] { null });
        assertEquals(5, builder.size());
        builder.add(Arrays.asList("4", "5"));
        assertEquals(7, builder.size());
        builder.add(new String[] { null });
        assertEquals(8, builder.size());
        builder.add(Arrays.asList("6", "7").stream());
        assertEquals(10, builder.size());
        builder.add(new String[] { null });
        assertEquals(11, builder.size());
        builder.add((Iterable<String>) Arrays.asList("8", "9"));
        assertEquals(13, builder.size());

        builder.add(new String[] { null });
        assertEquals(14, builder.size());

        builder.add((Iterable<String>) Arrays.asList("10", null));
        assertEquals(16, builder.size());
        builder.add(new String[] { null });
        assertEquals(17, builder.size());
    }

    @Test
    void shouldHandleAddAdditionalMethods() {
        final var builder = new CollectionBuilder<String>();
        builder.add("1");

        assertEquals(1, builder.size());

        assertTrue(builder.contains("1"));
        assertEquals("1", builder.iterator().next());
        builder.clear();
        assertEquals(0, builder.size());
        assertTrue(builder.isEmpty());
    }

    @Test
    void shouldHandleObjectMethods() {
        final var builder = new CollectionBuilder<String>();
        builder.add("1");

        assertNotNull(builder.toString());
        assertNotEquals(0, builder.hashCode());
        assertEquals(builder, builder);
    }

    @Test
    void shouldBuildCollectionVariants() {
        final var builder = new CollectionBuilder<>(mutableList("1", "2", "3", "4", "4"));

        assertMutable(builder.toMutableList());
        assertEquals(5, builder.toMutableList().size());

        assertImmutable(builder.toImmutableList());
        assertEquals(5, builder.toImmutableList().size());

        assertMutable(builder.toMutableSet());
        assertEquals(4, builder.toMutableSet().size());

        assertImmutable(builder.toImmutableSet());
        assertEquals(4, builder.toImmutableSet().size());

        assertMutable(builder.toMutableNavigableSet());
        assertEquals(4, builder.toMutableNavigableSet().size());

        assertImmutable(builder.toImmutableNavigableSet());
        assertEquals(4, builder.toImmutableNavigableSet().size());

        assertMutable(builder.toConcurrentList());
        assertEquals(5, builder.toConcurrentList().size());

        assertMutable(builder.toConcurrentSet());
        assertEquals(4, builder.toConcurrentSet().size());

        assertMutable(builder.toConcurrentNavigableSet());
        assertEquals(4, builder.toConcurrentNavigableSet().size());

    }

    @Test
    void shouldReturnArray() {
        final var builder = new CollectionBuilder<String>();
        assertNotNull(builder.toArray(String.class));
        assertEquals(0, builder.toArray(String.class).length);

        builder.add(mutableList("1", "2", "3", "4", "4"));
        assertNotNull(builder.toArray(String.class));
        assertEquals(5, builder.toArray(String.class).length);
    }

    @Test
    void shouldCreateCopyFromList() {
        final CollectionBuilder<String> builder = CollectionBuilder.copyFrom(immutableList("1", "2", "3"));
        builder.add("4");
        assertEquals(4, builder.toConcurrentNavigableSet().size());
    }

    @Test
    void shouldCreateCopyFromIterator() {
        final CollectionBuilder<String> builder = CollectionBuilder.copyFrom(immutableList("1", "2", "3").iterator());
        builder.add("4");
        assertEquals(4, builder.toConcurrentNavigableSet().size());
    }

    @Test
    void shouldCreateCopyFromIterable() {
        final CollectionBuilder<String> builder =
            CollectionBuilder.copyFrom((Iterable<String>) immutableList("1", "2", "3"));
        builder.add("4");
        assertEquals(4, builder.toConcurrentNavigableSet().size());
    }

    @Test
    void shouldCreateCopyFromStream() {
        final CollectionBuilder<String> builder = CollectionBuilder.copyFrom(immutableList("1", "2", "3").stream());
        builder.add("4");
        assertEquals(4, builder.toConcurrentNavigableSet().size());
    }

    @Test
    void shouldCreateCopyFromVarargs() {
        final CollectionBuilder<String> builder = CollectionBuilder.copyFrom("1", "2", "3");
        builder.add("4");
        assertEquals(4, builder.toConcurrentNavigableSet().size());
    }

    @Test
    void shouldCreateCopyFromSingleParam() {
        final CollectionBuilder<String> builder = CollectionBuilder.copyFrom("1");
        builder.add("4");
        assertEquals(2, builder.toConcurrentNavigableSet().size());
    }

    @Test
    void shouldSort() {
        final CollectionBuilder<String> builder = CollectionBuilder.copyFrom(immutableList("3", "2", "1"));
        assertEquals(Arrays.asList("3", "2", "1"), builder.toMutableList());
        builder.sort(Comparator.naturalOrder());
        assertEquals(Arrays.asList("1", "2", "3"), builder.toMutableList());
    }

    @Test
    void shouldSortNonLists() {
        final var builder = new CollectionBuilder<>(mutableSortedSet("3", "2", "1"));
        builder.sort(Comparator.naturalOrder());
        assertEquals(Arrays.asList("1", "2", "3"), builder.toMutableList());
    }

    @Test
    void shouldFilterNullsByDefault() {

        final List<String> testArray = new ArrayList<>(0);
        testArray.add("first");
        testArray.add(null);
        testArray.add("second");

        final var result = new CollectionBuilder<String>().add(testArray).toImmutableList();

        assertEquals(2, result.size(), "Only two entries expected");
        assertNotEquals(testArray, result);

    }

    static void assertMutable(final Collection<String> collection) {
        assertNotNull(collection);
        collection.add("I am mutable");
    }

    static void assertImmutable(final Collection<String> collection) {
        assertNotNull(collection);
        assertThrows(UnsupportedOperationException.class, () -> {
            collection.add("i am not mutable");
        });

    }
}
