package de.icw.util.formatting.template;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import de.icw.util.formatting.support.PersonDto;
import de.icw.util.formatting.support.PersonName;
import de.icw.util.formatting.support.RecordEntryPersonDto;
import de.icw.util.formatting.template.lexer.Lexer;
import de.icw.util.formatting.template.lexer.Lexer.ExpressionLanguage;
import de.icw.util.formatting.template.lexer.LexerBuilder;

@SuppressWarnings("javadoc")
public class TemplateFormatterTest {

    private static final String PERSON_NAME_FORMAT = "[familyName, ][givenName ][middleName]";

    private static final String PERSON_NAME_FORMAT_ANGLE_BRACKET =
        "Dr. <familyName, ><givenName ><middleName>";

    @Test
    public void completeFormatting() {
        final PersonDtoNameBuilder builder = new PersonDtoNameBuilder();
        final PersonName personName = builder.setFamilyName("FamilyName").setGivenName("GivenName")
                .setMiddleName("MiddleName").build();
        final TemplateFormatter<PersonName> formatter = getPersonNameFormatter();
        assertEquals("FamilyName, GivenName MiddleName", formatter.format(personName));
    }

    @Test
    public void formatWithLikelySoundsProperties() {
        final String myTemplate = "[familyName], [givenName], [middleName] [givenNameSuffix]";
        final PersonDtoNameBuilder builder = new PersonDtoNameBuilder();
        final PersonName personName = builder.setFamilyName("FamilyName").setGivenName("GivenName")
                .setMiddleName("MiddleName").setGivenNameSuffix("GivenNameSuffix").build();
        final TemplateFormatter<PersonName> formatter =
            TemplateFormatterImpl.createFormatter(myTemplate, PersonName.class);
        assertEquals("FamilyName, GivenName, MiddleName GivenNameSuffix",
                formatter.format(personName));
    }

    @Test
    public void formatWithLikelySoundsMissingProperties() {
        final String myTemplate = "[familyName], [givenName], [middleName] [givenNameSuffix]";
        final PersonDtoNameBuilder builder = new PersonDtoNameBuilder();
        final PersonName personName = builder.setFamilyName("FamilyName").setGivenName("GivenName")
                .setMiddleName("MiddleName").build();
        final TemplateFormatter<PersonName> formatter =
            TemplateFormatterImpl.createFormatter(myTemplate, PersonName.class);
        assertEquals("FamilyName, GivenName, MiddleName", formatter.format(personName));
    }

    @Test
    public void formatWithFirstMissing() {
        final PersonName personName = new PersonBuilder().setGivenName("Given").setMiddleName("Middle").build();
        final TemplateFormatter<PersonName> formatter = getPersonNameFormatterByLexer();
        assertEquals("Given Middle", formatter.format(personName));
    }

    @Test
    public void specialFormatForOnlyOneValue() {
        final RecordPersonDtoBuilder builder = new RecordPersonDtoBuilder();
        final PersonName personName = builder.setGivenName("Otto").build();
        final TemplateFormatter<PersonName> formatter = getPersonNameFormatter();
        assertEquals("Otto", formatter.format(personName));
    }

    @Test
    public void shouldPassValidation() {
        Validator.validateTemplate(PERSON_NAME_FORMAT, PersonName.class);

        Validator.validateTemplate(PERSON_NAME_FORMAT_ANGLE_BRACKET,
                createLexerAngleBrackets());
    }

    @Test
    public void shouldFailOnValidation() {
        assertThrows(IllegalArgumentException.class,
                () -> Validator.validateTemplate(PERSON_NAME_FORMAT, WrongDataObject.class));
    }

    @Test
    public void shouldFailOnValidationByLexer() {
        final Lexer<WrongDataObject> lexer =
            LexerBuilder.withExpressionLanguage(ExpressionLanguage.SIMPLE_ANGLE_BRACKET)
                    .build(WrongDataObject.class);
        assertThrows(IllegalArgumentException.class,
                () -> Validator.validateTemplate(PERSON_NAME_FORMAT_ANGLE_BRACKET, lexer));
    }

    @Test
    public void createdFormatterCanBeReused() {
        final String familyName = "Famname";
        final String givenName = "Given";

        final PersonName object1 =
            new RecordPersonDtoBuilder().setFamilyName(familyName).setGivenName(givenName)
                    .build();
        final PersonName object2 =
            new PersonBuilder().setFamilyName(familyName).setGivenName(givenName).build();

        final TemplateFormatter<PersonName> formatter = createFormatterForSource(object1);
        final String expected = familyName + ", " + givenName + " ";
        assertEquals(expected, formatter.format(object1));
        assertEquals(expected, formatter.format(object2));
    }

    @Test
    public void shouldRemoveUselessDelimiter() {
        final String familyName = anyValidString();
        final String givenName = anyValidString();
        final String myTemplate = "[familyName], [givenName], [middleName]";
        final PersonName object1 =
            new RecordPersonDtoBuilder().setFamilyName(familyName).setGivenName(givenName)
                    .build();

        final TemplateFormatter<PersonName> formatter =
            TemplateFormatterImpl.createFormatter(myTemplate, PersonName.class);
        final String expected = familyName + ", " + givenName;
        assertEquals(expected, formatter.format(object1));
    }

    @Test
    public void shouldRemoveDelimiterAtBeginning() {
        final String middle = anyValidString();
        final String givenName = anyValidString();
        final String myTemplate = "[familyName], [givenName], [middleName]";
        final PersonName object1 =
            new RecordPersonDtoBuilder().setMiddleName(middle).setGivenName(givenName).build();

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
    public void shouldProvideConditionalFormatting() {
        /*
         * implementation idea : use Guava JOINER for String Tokens in between
         * therefore tree graph is needed, no linear list is able to represent
         * this
         */
    }

    /* HELPER METHODS AND CLASSES */

    private static TemplateFormatter<PersonName> getPersonNameFormatter() {
        return TemplateFormatterImpl.createFormatter(PERSON_NAME_FORMAT, PersonName.class);
    }

    private static TemplateFormatter<PersonName> getPersonNameFormatterByLexer() {
        final Lexer<PersonName> lexer =
            LexerBuilder.useSimpleElWithSquaredBrackets().build(PersonName.class);
        return TemplateFormatterImpl.createFormatter(PERSON_NAME_FORMAT, lexer);
    }

    private static Lexer<PersonName> createLexerAngleBrackets() {
        return LexerBuilder.withExpressionLanguage(ExpressionLanguage.SIMPLE_ANGLE_BRACKET)
                .build(PersonName.class);
    }

    private static TemplateFormatter<PersonName> createFormatterForSource(final PersonName source) {
        return TemplateFormatterImpl.createFormatter(PERSON_NAME_FORMAT, source);
    }

    private static String anyValidString() {
        return "someString";
    }

    /**
     * Helper use PersonDto for PersonName
     */
    class PersonDtoNameBuilder {

        private String familyName;

        private String givenName;

        private String middleName;

        private String givenNameSuffix;

        PersonDtoNameBuilder setFamilyName(final String value) {
            familyName = value;
            return this;
        }

        PersonDtoNameBuilder setGivenName(final String value) {
            givenName = value;
            return this;
        }

        PersonDtoNameBuilder setGivenNameSuffix(final String value) {
            givenNameSuffix = value;
            return this;
        }

        PersonDtoNameBuilder setMiddleName(final String value) {
            middleName = value;
            return this;
        }

        PersonName build() {
            final PersonDto pdto = new PersonDto();
            pdto.setFamilyName(familyName);
            pdto.setGivenName(givenName);
            pdto.setGivenNameSuffix(givenNameSuffix);
            pdto.setMiddleName(middleName);
            return new PersonName(pdto);
        }
    }

    /**
     * Helper use RecordEntryPersonDto for PersonName
     */
    class RecordPersonDtoBuilder {

        private String familyName;

        private String givenName;

        private String middleName;

        RecordPersonDtoBuilder setFamilyName(final String value) {
            familyName = value;
            return this;
        }

        RecordPersonDtoBuilder setGivenName(final String value) {
            givenName = value;
            return this;
        }

        RecordPersonDtoBuilder setMiddleName(final String value) {
            middleName = value;
            return this;
        }

        PersonName build() {
            final RecordEntryPersonDto repdto = new RecordEntryPersonDto();
            repdto.setFamilyName(familyName);
            repdto.setGivenName(givenName);
            repdto.setMiddleName(middleName);
            return new PersonName(repdto);
        }
    }

    class PersonBuilder {

        private String familyName;

        private String givenName;

        private String middleName;

        PersonBuilder setFamilyName(final String value) {
            familyName = value;
            return this;
        }

        PersonBuilder setGivenName(final String value) {
            givenName = value;
            return this;
        }

        PersonBuilder setMiddleName(final String value) {
            middleName = value;
            return this;
        }

        PersonName build() {
            final RecordEntryPersonDto person = new RecordEntryPersonDto();
            person.setGivenName(givenName);
            person.setFamilyName(familyName);
            person.setMiddleName(middleName);
            return new PersonName(person);
        }

    }

}
