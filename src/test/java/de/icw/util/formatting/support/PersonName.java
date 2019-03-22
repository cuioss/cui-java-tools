package de.icw.util.formatting.support;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Strings.isNullOrEmpty;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableMap.Builder;

import de.icw.util.formatting.template.FormatterSupport;
import lombok.EqualsAndHashCode;
import lombok.ToString;

/**
 * PersonName consolidate several Person Objects by make a one-way
 * transformation. It implements {@linkplain FormatterSupport} interface.
 * <p/>
 * Supported Classes:
 * <ul>
 * <li>{@link PersonDto}</li>
 * <li>{@link RecordEntryPersonDto}</li>
 * </ul>
 * Mapping of properties will be done during construction. Properties which
 * can't be mapped will be initialize to null.
 *
 * @author i000576
 */
@ToString
@EqualsAndHashCode
public final class PersonName implements FormatterSupport, Serializable {

    private static final long serialVersionUID = 6986009875675450180L;

    /**
     * alternative {@link org.apache.commons.beanutils.BeanUtils} could provide
     * the same information, but than no filtering for properties will be
     * possible
     */
    private static final List<String> SUPPORTED_PROP_LIST = new ImmutableList.Builder<String>().add("familyNamePrefix")
            .add("familyName").add("familyBirthname").add("givenNamePrefix").add("givenName").add("givenNameSuffix")
            .add("givenBirthname").add("middleName").add("secondName").add("nickname").add("academicPrefix")
            .add("academicSuffix").add("professionalPrefix").add("professionalSuffix").add("genericPrefix")
            .add("genericSuffix").add("nobilityPrefix").add("nobilitySuffix").build();

    private String familyNamePrefix = null;

    private String familyName = null;

    private String familyBirthname = null;

    private String givenNamePrefix = null;

    private String givenName = null;

    private String givenNameSuffix = null;

    private String givenBirthname = null;

    private String middleName = null;

    private String secondName = null;

    private String nickname = null;

    private String academicPrefix = null;

    private String academicSuffix = null;

    private String professionalPrefix = null;

    private String professionalSuffix = null;

    private String genericPrefix = null;

    private String genericSuffix = null;

    private String nobilityPrefix = null;

    private String nobilitySuffix = null;

    private final Map<String, Serializable> propertyValues;

    /**
     * Default constructor initialize all property values to null
     */
    public PersonName() {
        propertyValues = retrieveAvailablePropertyValues();
    }

    /**
     * Map properties values to PersonName properties
     * 
     * @param facadePerson
     *            must not be null
     */
    public PersonName(final PersonDto facadePerson) {
        checkNotNull(facadePerson, "PersonDto must not be null");
        familyNamePrefix = facadePerson.getFamilyNamePrefix();
        familyName = facadePerson.getFamilyName();
        familyBirthname = facadePerson.getFamilyBirthname();
        givenName = facadePerson.getGivenName();
        givenNameSuffix = facadePerson.getGivenNameSuffix();
        givenBirthname = facadePerson.getGivenBirthname();
        middleName = facadePerson.getMiddleName();
        nickname = facadePerson.getNickname();
        academicPrefix = facadePerson.getAcademicPrefix();
        academicSuffix = facadePerson.getAcademicSuffix();
        professionalPrefix = facadePerson.getProfessionalPrefix();
        professionalSuffix = facadePerson.getProfessionalSuffix();
        genericPrefix = facadePerson.getGenericPrefix();
        genericSuffix = facadePerson.getGenericSuffix();
        nobilityPrefix = facadePerson.getNobilityPrefix();
        nobilitySuffix = facadePerson.getNobilitySuffix();
        propertyValues = retrieveAvailablePropertyValues();
    }

    /**
     * Map properties values to PersonName properties
     * 
     * @param recordEntryPerson
     */
    public PersonName(final RecordEntryPersonDto recordEntryPerson) {
        checkNotNull(recordEntryPerson, "RecordEntryPersonDto must not be null");
        familyName = recordEntryPerson.getFamilyName();
        givenNamePrefix = recordEntryPerson.getNamePrefix();
        givenName = recordEntryPerson.getGivenName();
        givenNameSuffix = recordEntryPerson.getNameSuffix();
        middleName = recordEntryPerson.getMiddleName();
        academicPrefix = recordEntryPerson.getAcademicTitle();
        propertyValues = retrieveAvailablePropertyValues();
    }

    private Map<String, Serializable> retrieveAvailablePropertyValues() {
        final Builder<String, Serializable> builder = ImmutableMap.builder();
        putIfNotNullOrEmpty(builder, "familyNamePrefix", familyNamePrefix);
        putIfNotNullOrEmpty(builder, "familyName", familyName);
        putIfNotNullOrEmpty(builder, "familyBirthname", familyBirthname);
        putIfNotNullOrEmpty(builder, "givenNamePrefix", givenNamePrefix);
        putIfNotNullOrEmpty(builder, "givenName", givenName);
        putIfNotNullOrEmpty(builder, "givenNameSuffix", givenNameSuffix);
        putIfNotNullOrEmpty(builder, "givenBirthname", givenBirthname);
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
        return builder.build();
    }

    private static void putIfNotNullOrEmpty(final Builder<String, Serializable> builder, final String key,
            final String value) {
        if (!isNullOrEmpty(value)) {
            builder.put(key, value);
        }
    }

    @Override
    public List<String> getSupportedPropertyNames() {
        return SUPPORTED_PROP_LIST;
    }

    @Override
    public Map<String, Serializable> getAvailablePropertyValues() {
        return propertyValues;
    }

}
