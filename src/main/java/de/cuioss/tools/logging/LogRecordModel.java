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
package de.cuioss.tools.logging;

import static de.cuioss.tools.string.MoreStrings.lenientFormat;
import static de.cuioss.tools.string.MoreStrings.nullToEmpty;

import java.util.function.Supplier;

import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;

/**
 * Represents a log-entry. Especially focuses on enforcing log-entry identifier,
 * see {@link #getPrefix()} and {@link #getIdentifier()}. The template mechanism
 * is the same as with {@link CuiLogger}, saying it accepts as well '%s' and
 * '{}' as placeholder, even mixed. To simplify usage the prefix string will
 * always be prepended on calling {@link #format(Object...)}
 *
 * @author Oliver Wolff
 *
 */
public class LogRecordModel implements LogRecord {

    private static final String PREFIX_IDENTIFIER_TEMPLATE = "%s-%s";
    private static final String AFTER_PREFIX = ": ";

    @Getter
    @NonNull
    private final String prefix;

    @Getter
    @NonNull
    private final Integer identifier;

    @Getter
    @NonNull
    private final String template;

    /** Tiniest of optimization. Needs to be verified. */
    private String parsedMessageTemplate;
    private String parsedIdentifier;

    protected String getParsedMessageTemplate() {
        if (null == parsedMessageTemplate) {
            parsedMessageTemplate = CuiLogger.SLF4J_PATTERN.matcher(nullToEmpty(getTemplate())).replaceAll("%s");
        }
        return parsedMessageTemplate;
    }

    @Override
    public String format(Object... parameter) {
        return new StringBuilder(resolveIdentifierString()).append(AFTER_PREFIX)
                .append(lenientFormat(getParsedMessageTemplate(), parameter)).toString();
    }

    @Override
    public Supplier<String> supplier(Object... parameter) {
        return () -> format(parameter);
    }

    @Override
    public String resolveIdentifierString() {
        if (null == parsedIdentifier) {
            parsedIdentifier = String.format(PREFIX_IDENTIFIER_TEMPLATE, getPrefix(), getIdentifier());
        }
        return parsedIdentifier;
    }

    @Builder
    private LogRecordModel(@NonNull String prefix, @NonNull Integer identifier, @NonNull String template) {
        this.prefix = prefix;
        this.identifier = identifier;
        this.template = template;
    }

}
