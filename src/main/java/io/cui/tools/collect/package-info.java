/**
 * Provides a number of utilities in the context of {@link java.util.Collection}s
 *
 * <ul>
 * <li>{@link io.cui.tools.collect.CollectionBuilder}: Unified builder for building arbitrary
 * Collections.</li>
 * <li>{@link io.cui.tools.collect.CollectionLiterals}: Provides literal-forms for creating
 * populated
 * collection instances. In essence its doing the same compared to the corresponding
 * com.google.common.collect types but with different semantics (like naming, types) and is designed
 * as a one stop utility class for all kind of Collection implementations including Sets and
 * Maps.</li>
 * <li>{@link io.cui.tools.collect.MapBuilder}: Builder for creating different kind of
 * {@link java.util.Map}s, similar to {@link io.cui.tools.collect.CollectionBuilder}</li>
 * <li>{@link io.cui.tools.collect.MoreCollections}: Utility Methods for Collections and some types
 * to be used in the context of Collections</li>
 * <li>{@link io.cui.tools.collect.PartialCollection}: Used for transporting partial views of
 * java.util.Collection. Currently there is one implementation available:
 * {@link io.cui.tools.collect.PartialArrayList}. This provides the factory method
 * {@link io.cui.tools.collect.PartialArrayList#of(java.util.List, int)} for quickly creating
 * instances</li>
 * </ul>
 */
package io.cui.tools.collect;
