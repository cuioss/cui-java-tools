package io.cui.tools.string;

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
class SplitterConfig {

    @Getter
    private final String separator;

    @Builder.Default
    @Getter
    private final boolean omitEmptyStrings = false;

    @Builder.Default
    @Getter
    private final boolean trimResults = false;

    @Builder.Default
    @Getter
    private final int maxItems = 0;

    @Builder.Default
    @Getter
    private final boolean doNotModifySeparatorString = false;

    SplitterConfigBuilder copy() {
        SplitterConfigBuilder copyBuilder = builder();
        copyBuilder.separator(getSeparator()).maxItems(getMaxItems())
                .doNotModifySeparatorString(isDoNotModifySeparatorString())
                .omitEmptyStrings(isOmitEmptyStrings()).trimResults(isTrimResults());
        return copyBuilder;
    }
}
