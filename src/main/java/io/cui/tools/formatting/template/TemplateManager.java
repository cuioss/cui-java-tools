package io.cui.tools.formatting.template;

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
            this.map = new HashMap<>();
        }

        /**
         * @param mapValue
         * @return This method should return the current object
         */
        public TemplateManagerBuilder<B> with(final Map<Locale, TemplateFormatter<B>> mapValue) {
            if (null != mapValue) {
                this.map.putAll(mapValue);
            }
            return this;
        }

        /**
         *
         * @param locale
         *            mapValue Map consists of key, which is {@link Locale}
         * @param formatter
         *            and a template formatter {@link TemplateFormatter}
         *
         * @return This method should add new locale to the current template
         */
        public TemplateManagerBuilder<B> with(final Locale locale, final TemplateFormatter<B> formatter) {
            this.map.put(locale, formatter);
            return this;
        }

        /**
         * @param formatter
         * @return TemplateManagerBuilder return the default formatter
         */
        public TemplateManagerBuilder<B> useAsDefault(final TemplateFormatter<B> formatter) {
            this.defFormatter = formatter;
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
