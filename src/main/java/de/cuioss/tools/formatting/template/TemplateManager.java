/*
 * Copyright 2023 the original author or authors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.tools.formatting.template;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;

/**
 * @author Sven Haag
 * @param <T> This should any value, which extends FormatterSupport interface
 *
 */
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public class TemplateManager<T extends FormatterSupport> {

    private final TemplateFormatter<T> defaultFormatter;

    private final Map<Locale, TemplateFormatter<T>> localeSpecificMap;

    /**
     * @param targetToFormat
     * @param locale
     * @return This should format the template with the location information
     */
    public String format(final T targetToFormat, final Locale locale) {
        if (localeSpecificMap.containsKey(locale)) {
            return localeSpecificMap.get(locale).format(targetToFormat);
        }
        return defaultFormatter.format(targetToFormat);
    }

    /**
     * Builder inner class for the template manager
     *
     * @param <B> at least {@link FormatterSupport}
     */
    public static class TemplateManagerBuilder<B extends FormatterSupport> {

        private final Map<Locale, TemplateFormatter<B>> map;

        private TemplateFormatter<B> defFormatter;

        /**
         * Constructor
         */
        public TemplateManagerBuilder() {
            map = new HashMap<>();
        }

        /**
         * @param mapValue
         * @return This method should return the current object
         */
        public TemplateManagerBuilder<B> with(final Map<Locale, TemplateFormatter<B>> mapValue) {
            if (null != mapValue) {
                map.putAll(mapValue);
            }
            return this;
        }

        /**
         *
         * @param locale    mapValue Map consists of key, which is {@link Locale}
         * @param formatter and a template formatter {@link TemplateFormatter}
         *
         * @return This method should add new locale to the current template
         */
        public TemplateManagerBuilder<B> with(final Locale locale, final TemplateFormatter<B> formatter) {
            map.put(locale, formatter);
            return this;
        }

        /**
         * @param formatter
         * @return TemplateManagerBuilder return the default formatter
         */
        public TemplateManagerBuilder<B> useAsDefault(final TemplateFormatter<B> formatter) {
            defFormatter = formatter;
            return this;
        }

        /**
         * @return This method builds the object with the given information.
         */
        public TemplateManager<B> build() {
            return new TemplateManager<>(defFormatter, map);
        }

    }

}
