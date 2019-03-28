# cuioss-java-utils
## What is it?
A number of additional utilites on top on guava-light

## de.icw.util.collect
- de.icw.util.collect.CollectionBuilder: Unified builder for building arbitrary Collections.
- de.icw.util.collect.CollectionLiterals: Provides literal-forms for creating populated collection instances. In essence its doing the same compared to the corresponding com.google.common.collect types but with different semantics (like naming, types) and is designed as a one stop utility class for all kind of Collection implementations including Sets and Maps.
- de.icw.util.collect.MoreCollections:  Utility Methods for Collections and some types to be used in the context of Collections
- de.icw.util.collect.PartialCollection: Used for transporting partial views of java.util.Collection. Currently there is one implementation available: de.icw.util.collect.PartialArrayList
