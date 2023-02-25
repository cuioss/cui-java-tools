package io.cui.tools.logging;

import static io.cui.tools.string.MoreStrings.lenientFormat;
import static io.cui.tools.string.MoreStrings.nullToEmpty;

import java.util.function.Supplier;

import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;

/**
 * Represents a log-entry. Especially focuses on enforcing log-entry identifier, see
 * {@link #getPrefix()} and {@link #getIdentifier()}. The template mechanism is the same as with
 * {@link CuiLogger}, saying it accepts as well '%s' and '{}' as placeholder, even mixed.
 * To simplify usage the prefix string will always be prepended on calling
 * {@link #format(Object...)}
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
        super();
        this.prefix = prefix;
        this.identifier = identifier;
        this.template = template;
    }

}
