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

    @SuppressWarnings("java:S2094")
    // owolff: workaround for javadoc-error, see
    // https://stackoverflow.com/questions/51947791/javadoc-cannot-find-symbol-error-when-using-lomboks-builder-annotation
    public static class JoinerConfigBuilder {
    }

    JoinerConfigBuilder copy() {
        return builder().separator(getSeparator()).useForNull(getUseForNull()).skipEmpty(isSkipEmpty())
                .skipBlank(isSkipBlank()).skipNulls(isSkipNulls());
    }
}
