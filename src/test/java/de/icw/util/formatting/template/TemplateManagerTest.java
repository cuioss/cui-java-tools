package de.icw.util.formatting.template;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNot.not;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HashMap;
import java.util.Locale;

import org.junit.jupiter.api.Test;

import de.icw.util.formatting.support.PersonDto;
import de.icw.util.formatting.support.PersonName;
import de.icw.util.formatting.template.TemplateManager.TemplateManagerBuilder;

@SuppressWarnings("javadoc")
public class TemplateManagerTest {

    TemplateManager<PersonName> manager;
    PersonName targetToFormat;
    String actual;

    @Test
    public void shouldSupportFormatInManyLangauages() {

        manager = templateManagerWithTwoLangaugesSupport();
        targetToFormat = anyPersonName();
        actual = manager.format(targetToFormat, Locale.GERMANY);

        // expected result givenName, familyName
        assertThat(actual, is("Hans, Müller"));

        final String resultUS = manager.format(targetToFormat, Locale.US);
        // expected result familyName, givenName
        assertThat(resultUS, is("Müller, Hans"));

        // expect fallback to default formatter
        final String resultDefault = manager.format(targetToFormat, Locale.CHINA);
        // expected result familyName
        assertThat(resultDefault, is("Müller"));

    }

    private static PersonName anyPersonName() {
        final PersonDto person = new PersonDto();
        person.setFamilyName("Müller");
        person.setGivenName("Hans");
        return new PersonName(person);
    }

    private static TemplateManager<PersonName> templateManagerWithTwoLangaugesSupport() {
        final TemplateManagerBuilder<PersonName> builder = new TemplateManager.TemplateManagerBuilder<>();

        return builder.useAsDeafult(getDeafultFormatter()).with(Locale.GERMANY, getFormatterForGermany())
                .with(Locale.US, getFormatterFoUs()).build();
    }

    private static TemplateFormatter<PersonName> getFormatterFoUs() {
        return TemplateFormatterImpl.createFormatter("[familyName], [givenName]", PersonName.class);
    }

    private static TemplateFormatter<PersonName> getFormatterForGermany() {
        // familyName, givenName
        return TemplateFormatterImpl.createFormatter("[givenName], [familyName]", PersonName.class);
    }

    private static TemplateFormatter<PersonName> getDeafultFormatter() {
        // default formatter - template only 'familyName'
        return TemplateFormatterImpl.createFormatter("[familyName]", PersonName.class);
    }

    @Test
    public void shouldReturnDefaultFormatter() {

        manager = templateManagerWithTwoLangaugesSupport();
        targetToFormat = anyPersonName();
        actual = manager.format(targetToFormat, Locale.FRENCH);

        assertNotEquals(actual, "Hans, Müller");
    }

    @Test
    public void shouldFail() {
        // expected = NullPointerException.class
        manager = templateManagerWithTwoLangaugesSupport();
        targetToFormat = anyPersonName();
        assertThrows(NullPointerException.class, () -> actual = manager.format(null, Locale.GERMANY));
    }

    @Test
    public void shouldNotBeEqual() {
        manager = templateManagerWithoutLocation();
        targetToFormat = anyPersonName();
        actual = manager.format(targetToFormat, Locale.GERMANY);
        assertThat(actual, is(not("Hans, Müller")));
    }

    @Test
    public void shouldNotBeEqual2() {
        manager = templateManagerWithoutOneLocation();
        targetToFormat = anyPersonName();
        actual = manager.format(targetToFormat, Locale.GERMANY);
        assertThat(actual, is("Hans, Müller"));
    }

    @Test
    public void shouldNotBeEqual3() {
        manager = templateManagerWithoutLocation2();
        targetToFormat = anyPersonName();
        actual = manager.format(targetToFormat, Locale.GERMANY);
        assertThat(actual, is(not("Hans, Müller")));
    }

    private static TemplateManager<PersonName> templateManagerWithoutLocation() {
        final TemplateManagerBuilder<PersonName> builder = new TemplateManager.TemplateManagerBuilder<>();
        return builder.useAsDeafult(getDeafultFormatter()).with(null).build();
    }

    private static TemplateManager<PersonName> templateManagerWithoutOneLocation() {
        final HashMap<Locale, TemplateFormatter<PersonName>> map = new HashMap<>();
        map.put(Locale.GERMANY, getFormatterForGermany());
        final TemplateManagerBuilder<PersonName> builder = new TemplateManager.TemplateManagerBuilder<>();
        return builder.useAsDeafult(getDeafultFormatter()).with(map).build();
    }

    private static TemplateManager<PersonName> templateManagerWithoutLocation2() {
        final HashMap<Locale, TemplateFormatter<PersonName>> map = new HashMap<>();
        map.put(null, null);
        final TemplateManagerBuilder<PersonName> builder = new TemplateManager.TemplateManagerBuilder<>();
        return builder.useAsDeafult(getDeafultFormatter()).with(map).build();
    }

}
