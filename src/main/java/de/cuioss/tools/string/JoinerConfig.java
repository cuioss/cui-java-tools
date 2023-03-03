package de.cuioss.tools.string;

import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

/**
 * Encapsulates configuration for the Splitter
 *
 * @author Oliver Wolff
 *
 */
@Builder
@EqualsAndHashCode
@ToString
@SuppressWarnings("squid:S1170") // owolff: False positive, sonar does not recognize Lomboks
                                 // Builder-Default annotations here
class JoinerConfig {

    @Getter
    private final String separator;

    @Builder.Default
    @Getter
    private final boolean skipNulls = false;

    @Builder.Default
    @Getter
    private final boolean skipEmpty = false;

    @Builder.Default
    @Getter
    private final boolean skipBlank = false;

    @Builder.Default
    @Getter
    private final String useForNull = "null";

    JoinerConfigBuilder copy() {
        var copyBuilder = builder();
        copyBuilder.separator(getSeparator()).useForNull(getUseForNull()).skipEmpty(isSkipEmpty())
                .skipBlank(isSkipBlank())
                .skipNulls(isSkipNulls());
        return copyBuilder;
    }
}
