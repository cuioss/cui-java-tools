package io.cui.tools.formatting.support;

import static io.cui.tools.collect.CollectionLiterals.immutableMap;
import static io.cui.tools.string.MoreStrings.isEmpty;

import java.io.Serializable;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import io.cui.tools.collect.CollectionBuilder;
import io.cui.tools.formatting.template.FormatterSupport;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * PersonName consolidate several Person Objects by make a one-way
 * transformation. It implements {@linkplain FormatterSupport} interface.
 * <p/>
 *
 * Mapping of properties will be done during construction. Properties which
 * can't be mapped will be initialized to null.
 *
 * @author Eugen Fischer
 */

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public final class PersonName implements FormatterSupport, Serializable {

    private static final long serialVersionUID = -6138413254405190225L;
    /**
     * alternative reflection could provide the same information, but than no filtering for
     * properties will be possible
     */
    private static final List<String> SUPPORTED_PROP_LIST = new CollectionBuilder<String>().add("familyNamePrefix")
            .add("familyName").add("familyBirthName").add("givenNamePrefix").add("givenName").add("givenNameSuffix")
            .add("givenBirthName").add("middleName").add("secondName").add("nickname").add("academicPrefix")
            .add("academicSuffix").add("professionalPrefix").add("professionalSuffix").add("genericPrefix")
            .add("genericSuffix").add("nobilityPrefix").add("nobilitySuffix").toImmutableList();

    private String familyNamePrefix;

    private String familyName;

    private String familyBirthName;

    private String givenNamePrefix;

    private String givenName;

    private String givenNameSuffix;

    private String givenBirthName;

    private String middleName;

    private String secondName;

    private String nickname;

    private String academicPrefix;

    private String academicSuffix;

    private String professionalPrefix;

    private String professionalSuffix;

    private String genericPrefix;

    private String genericSuffix;

    private String nobilityPrefix;

    private String nobilitySuffix;

    private Map<String, Serializable> retrieveAvailablePropertyValues() {
        final Map<String, Serializable> builder = new HashMap<>();
        putIfNotNullOrEmpty(builder, "familyNamePrefix", familyNamePrefix);
        putIfNotNullOrEmpty(builder, "familyName", familyName);
        putIfNotNullOrEmpty(builder, "familyBirthName", familyBirthName);
        putIfNotNullOrEmpty(builder, "givenNamePrefix", givenNamePrefix);
        putIfNotNullOrEmpty(builder, "givenName", givenName);
        putIfNotNullOrEmpty(builder, "givenNameSuffix", givenNameSuffix);
        putIfNotNullOrEmpty(builder, "givenBirthName", givenBirthName);
        putIfNotNullOrEmpty(builder, "middleName", middleName);
        putIfNotNullOrEmpty(builder, "secondName", secondName);
        putIfNotNullOrEmpty(builder, "nickname", nickname);
        putIfNotNullOrEmpty(builder, "academicPrefix", academicPrefix);
        putIfNotNullOrEmpty(builder, "academicSuffix", academicSuffix);
        putIfNotNullOrEmpty(builder, "professionalPrefix", professionalPrefix);
        putIfNotNullOrEmpty(builder, "professionalSuffix", professionalSuffix);
        putIfNotNullOrEmpty(builder, "genericPrefix", genericPrefix);
        putIfNotNullOrEmpty(builder, "genericSuffix", genericSuffix);
        putIfNotNullOrEmpty(builder, "nobilityPrefix", nobilityPrefix);
        putIfNotNullOrEmpty(builder, "nobilitySuffix", nobilitySuffix);
        return immutableMap(builder);
    }

    private static void putIfNotNullOrEmpty(final Map<String, Serializable> builder, final String key,
            final String value) {
        if (!isEmpty(value)) {
            builder.put(key, value);
        }
    }

    @Override
    public List<String> getSupportedPropertyNames() {
        return SUPPORTED_PROP_LIST;
    }

    @Override
    public Map<String, Serializable> getAvailablePropertyValues() {
        return retrieveAvailablePropertyValues();
    }

}
