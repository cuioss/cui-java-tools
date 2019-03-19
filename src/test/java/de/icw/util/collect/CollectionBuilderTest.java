package de.icw.util.collect;

import static de.icw.util.collect.CollectionLiterals.immutableList;
import static de.icw.util.collect.CollectionLiterals.mutableList;
import static de.icw.util.collect.CollectionLiterals.mutableSortedSet;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.Optional;

import org.junit.jupiter.api.Test;

class CollectionBuilderTest {

    @Test
    void shouldHandleAddMethods() {
        CollectionBuilder<String> builder = new CollectionBuilder<>();
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

        builder.addIfNotNull((String[]) null);
        assertEquals(10, builder.size());
    }

    @Test
    void shouldHandleAddIfPresentMethods() {
        CollectionBuilder<String> builder = new CollectionBuilder<>();
        builder.addIfNotNull("1");
        assertEquals(1, builder.size());
        builder.addIfNotNull("2", "3");
        assertEquals(3, builder.size());
        builder.addIfNotNull(Arrays.asList("4", "5"));
        assertEquals(5, builder.size());
        builder.addIfNotNull(Arrays.asList("6", "7").stream());
        assertEquals(7, builder.size());
        builder.addIfNotNull((Iterable<String>) Arrays.asList("8", "9"));
        assertEquals(9, builder.size());

        builder.addIfNotNull((Iterable<String>) Arrays.asList("10", null));
        assertEquals(10, builder.size());
    }

    @Test
    void shouldHandleAddAdditionalMethods() {
        CollectionBuilder<String> builder = new CollectionBuilder<>();
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
        CollectionBuilder<String> builder = new CollectionBuilder<>();
        builder.add("1");

        assertNotNull(builder.toString());
        assertNotNull(builder.hashCode());
        assertEquals(builder, builder);
    }

    @Test
    void shouldBuildCollectionVariants() {
        CollectionBuilder<String> builder = new CollectionBuilder<>(mutableList("1", "2", "3", "4", "4"));

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
    void shouldCreateCopyFromList() {
        CollectionBuilder<String> builder = CollectionBuilder.copyFrom(immutableList("1", "2", "3"));
        builder.add("4");
        assertEquals(4, builder.toConcurrentNavigableSet().size());
    }

    @Test
    void shouldCreateCopyFromIterator() {
        CollectionBuilder<String> builder = CollectionBuilder.copyFrom(immutableList("1", "2", "3").iterator());
        builder.add("4");
        assertEquals(4, builder.toConcurrentNavigableSet().size());
    }

    @Test
    void shouldCreateCopyFromIterable() {
        CollectionBuilder<String> builder = CollectionBuilder.copyFrom((Iterable<String>) immutableList("1", "2", "3"));
        builder.add("4");
        assertEquals(4, builder.toConcurrentNavigableSet().size());
    }

    @Test
    void shouldCreateCopyFromStream() {
        CollectionBuilder<String> builder = CollectionBuilder.copyFrom(immutableList("1", "2", "3").stream());
        builder.add("4");
        assertEquals(4, builder.toConcurrentNavigableSet().size());
    }

    @Test
    void shouldCreateCopyFromVarargs() {
        CollectionBuilder<String> builder = CollectionBuilder.copyFrom("1", "2", "3");
        builder.add("4");
        assertEquals(4, builder.toConcurrentNavigableSet().size());
    }

    @Test
    void shouldCreateCopyFromSingleParam() {
        CollectionBuilder<String> builder = CollectionBuilder.copyFrom("1");
        builder.add("4");
        assertEquals(2, builder.toConcurrentNavigableSet().size());
    }

    @Test
    void shouldSort() {
        CollectionBuilder<String> builder = CollectionBuilder.copyFrom(immutableList("3", "2", "1"));
        assertEquals(Arrays.asList("3", "2", "1"), builder.toMutableList());
        builder.sort(Comparator.naturalOrder());
        assertEquals(Arrays.asList("1", "2", "3"), builder.toMutableList());
    }

    @Test
    void shouldSortNonLists() {
        CollectionBuilder<String> builder = new CollectionBuilder<>(mutableSortedSet("3", "2", "1"));
        builder.sort(Comparator.naturalOrder());
        assertEquals(Arrays.asList("1", "2", "3"), builder.toMutableList());
    }

    static final void assertMutable(Collection<String> collection) {
        assertNotNull(collection);
        collection.add("I am mutable");
    }

    static final void assertImmutable(Collection<String> collection) {
        assertNotNull(collection);
        assertThrows(UnsupportedOperationException.class, () -> {
            collection.add("i am not mutable");
        });

    }
}
