package de.icw.util.formatting.template.token;

import static com.google.common.base.Preconditions.checkNotNull;

import java.io.Serializable;

import de.icw.util.formatting.template.FormatterSupport;
import lombok.EqualsAndHashCode;
import lombok.ToString;

/**
 * Simple String token, this token returns always his value on
 * {@linkplain #substituteAttribute(FormatterSupport)}
 *
 * @author Eugen Fischer
 */
@ToString
@EqualsAndHashCode
public class StringToken implements Token, Serializable {

    private static final long serialVersionUID = 6377388001925442782L;

    private final String value;

    /**
     * @param value must not be null
     */
    public StringToken(final String value) {
        this.value = checkNotNull(value);
    }

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
