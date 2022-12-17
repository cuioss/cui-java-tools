package io.cui.util.formatting.template;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import io.cui.util.formatting.support.PersonName;
import io.cui.util.formatting.template.lexer.Lexer;
import io.cui.util.formatting.template.lexer.LexerBuilder;

class TemplateFormatterTest {

    private static final String PERSON_NAME_FORMAT = "[familyName, ][givenName ][middleName]";

    @Test
    void completeFormatting() {

        final PersonName personName = PersonName.builder()
            .familyName("FamilyName")
            .givenName("GivenName")
            .middleName("MiddleName")
            .build();

        final TemplateFormatter<PersonName> formatter = getPersonNameFormatter();

        assertEquals("FamilyName, GivenName MiddleName", formatter.format(personName));
    }

    @Test
    void completeFormattingWithStrict() {

        final PersonName personName = PersonName.builder()
            .familyName("FamilyName")
            .givenName("GivenName")
            .middleName("MiddleName")
            .build();

        final TemplateFormatter<PersonName> formatter =
            TemplateFormatterImpl.createFormatter(PERSON_NAME_FORMAT, PersonName.class, true);

        assertEquals("FamilyName, GivenName MiddleName", formatter.format(personName));
    }

    @Test
    void formatWithLikelySoundsProperties() {

        final String myTemplate = "[familyName], [givenName], [middleName] [givenNameSuffix]";

        final PersonName personName = PersonName.builder()
            .familyName("FamilyName")
            .givenName("GivenName")
            .middleName("MiddleName")
            .givenNameSuffix("GivenNameSuffix")
            .build();

        final TemplateFormatter<PersonName> formatter =
            TemplateFormatterImpl.createFormatter(myTemplate, PersonName.class);

        assertEquals("FamilyName, GivenName, MiddleName GivenNameSuffix",
            formatter.format(personName));
    }

    @Test
    void formatWithLikelySoundsPropertiesAndStrict() {

        final String myTemplate = "[familyName], [givenName], [middleName] [givenNameSuffix]";

        final PersonName personName = PersonName.builder()
            .familyName("FamilyName")
            .givenName("GivenName")
            .middleName("MiddleName")
            .givenNameSuffix("GivenNameSuffix")
            .build();

        final TemplateFormatter<PersonName> formatter =
            TemplateFormatterImpl.createFormatter(myTemplate, PersonName.class, true);

        assertEquals("FamilyName, GivenName, MiddleName GivenNameSuffix",
            formatter.format(personName));
    }

    @Test
    void formatWithPropertiesWithSuffixes() {

        final String myTemplate = "[familyNamee], [givenNamenn], [middleNameö] [givenNameSuffix-]";

        final PersonName personName = PersonName.builder()
            .familyName("FamilyName")
            .givenName("GivenName")
            .middleName("MiddleName")
            .givenNameSuffix("GivenNameSuffix")
            .build();

        final TemplateFormatter<PersonName> formatter =
            TemplateFormatterImpl.createFormatter(myTemplate, PersonName.class);

        assertEquals("FamilyNamee, GivenNamenn, MiddleNameö GivenNameSuffix-",
            formatter.format(personName));
    }

    @Test
    void formatWithPropertiesWithSuffixesAndStrict() {

        final String myTemplate = "[familyNamee], [givenNamenn], [middleNameö] [givenNameSuffix-]";

        final PersonName personName = PersonName.builder()
            .familyName("FamilyName")
            .givenName("GivenName")
            .middleName("MiddleName")
            .givenNameSuffix("GivenNameSuffix")
            .build();

        final TemplateFormatter<PersonName> formatter =
            TemplateFormatterImpl.createFormatter(myTemplate, PersonName.class, true);

        assertThrows(IllegalArgumentException.class, () -> {
            assertEquals("FamilyName, GivenName, MiddleName GivenNameSuffix",
                formatter.format(personName));
        });
    }

    @Test
    void formatWithLikelySoundsMissingProperties() {
        final String myTemplate = "[familyName], [givenName], [middleName] [givenNameSuffix]";

        final PersonName personName = PersonName.builder()
            .familyName("FamilyName")
            .givenName("GivenName")
            .middleName("MiddleName")
            .build();

        final TemplateFormatter<PersonName> formatter =
            TemplateFormatterImpl.createFormatter(myTemplate, PersonName.class);
        assertEquals("FamilyName, GivenName, MiddleName", formatter.format(personName));
    }

    @Test
    void formatWithFirstMissing() {
        final PersonName personName = PersonName.builder().givenName("Given").middleName("Middle").build();
        final TemplateFormatter<PersonName> formatter = getPersonNameFormatterByLexer();
        assertEquals("Given Middle", formatter.format(personName));
    }

    @Test
    void specialFormatForOnlyOneValue() {
        final PersonName personName = PersonName.builder().givenName("Otto").build();
        final TemplateFormatter<PersonName> formatter = getPersonNameFormatter();
        assertEquals("Otto", formatter.format(personName));
    }

    @Test
    void createdFormatterCanBeReused() {
        final String familyName = "Famname";
        final String givenName = "Given";

        final PersonName object1 = PersonName.builder().familyName(familyName).givenName(givenName).build();
        final PersonName object2 =
            PersonName.builder().familyName(familyName).givenName(givenName).givenBirthName("other one").build();

        assertNotEquals(object1, object2);

        final TemplateFormatter<PersonName> formatter = createFormatterForSource(object1);
        final String expected = familyName + ", " + givenName + " ";
        assertEquals(expected, formatter.format(object1));
        assertEquals(expected, formatter.format(object2));
    }

    @Test
    void shouldRemoveUselessDelimiter() {
        final String familyName = anyValidString();
        final String givenName = anyValidString();
        final String myTemplate = "[familyName], [givenName], [middleName]";
        final PersonName object1 = PersonName.builder().familyName(familyName).givenName(givenName).build();

        final TemplateFormatter<PersonName> formatter =
            TemplateFormatterImpl.createFormatter(myTemplate, PersonName.class);
        final String expected = familyName + ", " + givenName;
        assertEquals(expected, formatter.format(object1));
    }

    @Test
    void shouldRemoveDelimiterAtBeginning() {
        final String middle = anyValidString();
        final String givenName = anyValidString();
        final String myTemplate = "[familyName], [givenName], [middleName]";
        final PersonName object1 = PersonName.builder().middleName(middle).givenName(givenName).build();

        final TemplateFormatter<PersonName> formatter =
            TemplateFormatterImpl.createFormatter(myTemplate, PersonName.class);
        final String expected = givenName + ", " + middle;
        assertEquals(expected, formatter.format(object1));
    }

    /**
     * Test Idea : Separator should be added if both token are available: -
     * [[token1], [token2]] than VALUE1, VALUE2 are displayed - if token 2 is
     * missing no separator will be added : VALUE1 - if token 1 is missing no
     * separator will be added : VALUE2
     */
    void shouldProvideConditionalFormatting() {
        /*
         * implementation idea : use Guava JOINER for String Tokens in between
         * therefore tree graph is needed, no linear list is able to represent
         * this
         */
    }

    /* HELPER METHODS AND CLASSES */

    private static TemplateFormatter<PersonName> getPersonNameFormatter() {
        return TemplateFormatterImpl.TemplateBuilder.useTemplate(PERSON_NAME_FORMAT).forType(PersonName.class);
    }

    private static TemplateFormatter<PersonName> getPersonNameFormatterByLexer() {
        final Lexer<PersonName> lexer =
            LexerBuilder.useSimpleElWithSquaredBrackets().build(PersonName.class);
        return TemplateFormatterImpl.createFormatter(PERSON_NAME_FORMAT, lexer);
    }

    private static TemplateFormatter<PersonName> createFormatterForSource(final PersonName source) {
        return TemplateFormatterImpl.createFormatter(PERSON_NAME_FORMAT, source);
    }

    private static String anyValidString() {
        return "someString";
    }

}
