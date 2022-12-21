package io.cui.tools.formatting.template.token;

import io.cui.tools.formatting.template.FormatterSupport;
import lombok.EqualsAndHashCode;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

/**
 * Simple String token, this token returns always his value on
 * {@linkplain #substituteAttribute(FormatterSupport)}
 *
 * @author Eugen Fischer
 */
@ToString
@EqualsAndHashCode
@RequiredArgsConstructor
public class StringToken implements Token {

    private static final long serialVersionUID = 6377388001925442782L;

    @NonNull
    private final String value;

    /**
     * returns always stored string value
     */
    @Override
    public String substituteAttribute(final FormatterSupport content) {
        return value;
    }

    @Override
    public boolean isStringToken() {
        return true;
    }

}
