# cui-java-utils

## Status
[![Build Status](https://travis-ci.com/cuioss/cui-java-utils.svg?branch=master)](https://travis-ci.org/cuioss/cui-java-utils)
[![License](http://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)
[![Maven](https://img.shields.io/maven-metadata/v/http/central.maven.org/maven2/com/github/cuioss/cui-java-utils/maven-metadata.xml.svg)](http://central.maven.org/maven2/com/github/cuioss/cui-java-utils/)

## What is it?
A number of additional utilities on top on [guava-light](https://github.com/cuioss/guava-light) 

## de.icw.util.collect
- de.icw.util.collect.CollectionBuilder: Unified builder for building arbitrary Collections.
- de.icw.util.collect.CollectionLiterals: Provides literal-forms for creating populated collection instances. In essence its doing the same compared to the corresponding com.google.common.collect types but with different semantics (like naming, types) and is designed as a one stop utility class for all kind of Collection implementations including Sets and Maps.
- de.icw.util.collect.MoreCollections:  Utility Methods for Collections and some types to be used in the context of Collections
- de.icw.util.collect.PartialCollection: Used for transporting partial views of java.util.Collection. Currently there is one implementation available: de.icw.util.collect.PartialArrayList

## de.icw.util.formatting
Configurable formatting for complex structures, see package-javadoc for details.

## de.icw.util.logging
Simple wrapper around java.util.logging.Logger that simplify its usage. In addition it provides a similar api like slf4j. See javadoc of de.icw.util.logging.Logger for details.

## de.icw.util.net
- de.icw.util.net.UrlHelper: Provides some convenience methods for handling url strings

## de.icw.util.primitives
- de.icw.util.primitives.MoreStrings: Provides some extensions to String handling like com.google.common.base.Strings

## de.icw.util.reflect
- de.icw.util.reflect.MoreReflection: Provides a number of methods simplifying the usage of Reflection-based access
