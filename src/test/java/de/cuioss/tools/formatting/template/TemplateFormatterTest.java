/*
 * Copyright © 2025 CUI-OpenSource-Software (info@cuioss.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.tools.formatting.template;

import de.cuioss.tools.formatting.support.PersonName;
import de.cuioss.tools.formatting.template.lexer.Lexer;
import de.cuioss.tools.formatting.template.lexer.LexerBuilder;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class TemplateFormatterTest {

    private static final String PERSON_NAME_FORMAT = "[familyName, ][givenName ][middleName]";

    @Test
    void completeFormatting() {

        final var personName = PersonName.builder().familyName("FamilyName").givenName("GivenName")
                .middleName("MiddleName").build();

        final var formatter = getPersonNameFormatter();

        assertEquals("FamilyName, GivenName MiddleName", formatter.format(personName));
    }

    @Test
    void completeFormattingWithStrict() {

        final var personName = PersonName.builder().familyName("FamilyName").givenName("GivenName")
                .middleName("MiddleName").build();

        final TemplateFormatter<PersonName> formatter = TemplateFormatterImpl.createFormatter(PERSON_NAME_FORMAT,
                PersonName.class, true);

        assertEquals("FamilyName, GivenName MiddleName", formatter.format(personName));
    }

    @Test
    void formatWithLikelySoundsProperties() {

        final var myTemplate = "[familyName], [givenName], [middleName] [givenNameSuffix]";

        final var personName = PersonName.builder().familyName("FamilyName").givenName("GivenName")
                .middleName("MiddleName").givenNameSuffix("GivenNameSuffix").build();

        final TemplateFormatter<PersonName> formatter = TemplateFormatterImpl.createFormatter(myTemplate,
                PersonName.class);

        assertEquals("FamilyName, GivenName, MiddleName GivenNameSuffix", formatter.format(personName));
    }

    @Test
    void formatWithLikelySoundsPropertiesAndStrict() {

        final var myTemplate = "[familyName], [givenName], [middleName] [givenNameSuffix]";

        final var personName = PersonName.builder().familyName("FamilyName").givenName("GivenName")
                .middleName("MiddleName").givenNameSuffix("GivenNameSuffix").build();

        final TemplateFormatter<PersonName> formatter = TemplateFormatterImpl.createFormatter(myTemplate,
                PersonName.class, true);

        assertEquals("FamilyName, GivenName, MiddleName GivenNameSuffix", formatter.format(personName));
    }

    @Test
    void formatWithPropertiesWithSuffixes() {

        final var myTemplate = "[familyNamee], [givenNamenn], [middleNameö] [givenNameSuffix-]";

        final var personName = PersonName.builder().familyName("FamilyName").givenName("GivenName")
                .middleName("MiddleName").givenNameSuffix("GivenNameSuffix").build();

        final TemplateFormatter<PersonName> formatter = TemplateFormatterImpl.createFormatter(myTemplate,
                PersonName.class);

        assertEquals("FamilyNamee, GivenNamenn, MiddleNameö GivenNameSuffix-", formatter.format(personName));
    }

    @Test
    void formatWithPropertiesWithSuffixesAndStrict() {

        final var myTemplate = "[familyNamee], [givenNamenn], [middleNameö] [givenNameSuffix-]";

        final var personName = PersonName.builder().familyName("FamilyName").givenName("GivenName")
                .middleName("MiddleName").givenNameSuffix("GivenNameSuffix").build();

        final TemplateFormatter<PersonName> formatter = TemplateFormatterImpl.createFormatter(myTemplate,
                PersonName.class, true);

        assertThrows(IllegalArgumentException.class, () ->
                formatter.format(personName));
    }

    @Test
    void formatWithLikelySoundsMissingProperties() {
        final var myTemplate = "[familyName], [givenName], [middleName] [givenNameSuffix]";

        final var personName = PersonName.builder().familyName("FamilyName").givenName("GivenName")
                .middleName("MiddleName").build();

        final TemplateFormatter<PersonName> formatter = TemplateFormatterImpl.createFormatter(myTemplate,
                PersonName.class);
        assertEquals("FamilyName, GivenName, MiddleName", formatter.format(personName));
    }

    @Test
    void formatWithFirstMissing() {
        final var personName = PersonName.builder().givenName("Given").middleName("Middle").build();
        final var formatter = getPersonNameFormatterByLexer();
        assertEquals("Given Middle", formatter.format(personName));
    }

    @Test
    void specialFormatForOnlyOneValue() {
        final var personName = PersonName.builder().givenName("Otto").build();
        final var formatter = getPersonNameFormatter();
        assertEquals("Otto", formatter.format(personName));
    }

    @Test
    void createdFormatterCanBeReused() {
        final var familyName = "Famname";
        final var givenName = "Given";

        final var object1 = PersonName.builder().familyName(familyName).givenName(givenName).build();
        final var object2 = PersonName.builder().familyName(familyName).givenName(givenName).givenBirthName("other one")
                .build();

        assertNotEquals(object1, object2);

        final var formatter = createFormatterForSource(object1);
        final var expected = familyName + ", " + givenName + " ";
        assertEquals(expected, formatter.format(object1));
        assertEquals(expected, formatter.format(object2));
    }

    @Test
    void shouldRemoveUselessDelimiter() {
        final var familyName = anyValidString();
        final var givenName = anyValidString();
        final var myTemplate = "[familyName], [givenName], [middleName]";
        final var object1 = PersonName.builder().familyName(familyName).givenName(givenName).build();

        final TemplateFormatter<PersonName> formatter = TemplateFormatterImpl.createFormatter(myTemplate,
                PersonName.class);
        final var expected = familyName + ", " + givenName;
        assertEquals(expected, formatter.format(object1));
    }

    @Test
    void shouldRemoveDelimiterAtBeginning() {
        final var middle = anyValidString();
        final var givenName = anyValidString();
        final var myTemplate = "[familyName], [givenName], [middleName]";
        final var object1 = PersonName.builder().middleName(middle).givenName(givenName).build();

        final TemplateFormatter<PersonName> formatter = TemplateFormatterImpl.createFormatter(myTemplate,
                PersonName.class);
        final var expected = givenName + ", " + middle;
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
         * implementation idea : use Guava JOINER for String Tokens in between therefore
         * tree graph is needed, no linear list is able to represent this
         */
    }

    /* HELPER METHODS AND CLASSES */

    private static TemplateFormatter<PersonName> getPersonNameFormatter() {
        return TemplateFormatterImpl.TemplateBuilder.useTemplate(PERSON_NAME_FORMAT).forType(PersonName.class);
    }

    private static TemplateFormatter<PersonName> getPersonNameFormatterByLexer() {
        final Lexer<PersonName> lexer = LexerBuilder.useSimpleElWithSquaredBrackets().build(PersonName.class);
        return TemplateFormatterImpl.createFormatter(PERSON_NAME_FORMAT, lexer);
    }

    private static TemplateFormatter<PersonName> createFormatterForSource(final PersonName source) {
        return TemplateFormatterImpl.createFormatter(PERSON_NAME_FORMAT, source);
    }

    private static String anyValidString() {
        return "someString";
    }

}
