/**
 * Provides a number of utilities in the context of {@link java.util.Collection}s
 *
 * <ul>
 * <li>{@link de.icw.util.collect.CollectionBuilder}: Unified builder for building arbitrary
 * Collections.</li>
 * <li>{@link de.icw.util.collect.CollectionLiterals}: Provides literal-forms for creating populated
 * collection instances. In essence its doing the same compared to the corresponding
 * com.google.common.collect types but with different semantics (like naming, types) and is designed
 * as a one stop utility class for all kind of Collection implementations including Sets and
 * Maps.</li>
 * <li>{@link de.icw.util.collect.MoreCollections}: Utility Methods for Collections and some types
 * to
 * be used in the context of Collections</li>
 * <li>{@link de.icw.util.collect.PartialCollection}: Used for transporting partial views of
 * java.util.Collection. Currently there is one implementation available:
 * {@link de.icw.util.collect.PartialArrayList}</li>
 * </ul>
 */
package de.icw.util.collect;
