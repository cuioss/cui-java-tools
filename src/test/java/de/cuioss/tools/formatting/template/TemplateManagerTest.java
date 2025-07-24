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
import de.cuioss.tools.formatting.template.TemplateManager.TemplateManagerBuilder;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TemplateManagerTest {

    private TemplateManager<PersonName> manager;
    private PersonName targetToFormat;
    private String actual;

    @Test
    void shouldSupportFormatInManyLanguages() {

        manager = templateManagerWithTwoLanguagesSupport();
        targetToFormat = anyPersonName();
        actual = manager.format(targetToFormat, Locale.GERMANY);

        // expected result givenName, familyName
        assertEquals("Hans, M\00FCller", actual);

        final var resultUS = manager.format(targetToFormat, Locale.US);
        // expected result familyName, givenName
        assertEquals("M\00FCller, Hans", resultUS);

        // expect fallback to default formatter
        final var resultDefault = manager.format(targetToFormat, Locale.CHINA);
        // expected result familyName
        assertEquals("M\00FCller", resultDefault);

    }

    private static PersonName anyPersonName() {
        final var person = new PersonName();
        person.setFamilyName("M\00FCller");
        person.setGivenName("Hans");
        return person;
    }

    private static TemplateManager<PersonName> templateManagerWithTwoLanguagesSupport() {
        final var builder = new TemplateManagerBuilder<PersonName>();

        return builder.useAsDefault(getDeafultFormatter()).with(Locale.GERMANY, getFormatterForGermany())
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
    void shouldReturnDefaultFormatter() {

        manager = templateManagerWithTwoLanguagesSupport();
        targetToFormat = anyPersonName();
        actual = manager.format(targetToFormat, Locale.FRENCH);

        assertNotEquals("Hans, M\00FCller", actual);
    }

    @Test
    void shouldFail() {
        // expected = NullPointerException.class
        manager = templateManagerWithTwoLanguagesSupport();
        targetToFormat = anyPersonName();
        assertThrows(NullPointerException.class, () -> actual = manager.format(null, Locale.GERMANY));
    }

    @Test
    void shouldNotBeEqual() {
        manager = templateManagerWithoutLocation();
        targetToFormat = anyPersonName();
        actual = manager.format(targetToFormat, Locale.GERMANY);
        assertNotEquals("Hans, M\00FCller", actual);
    }

    @Test
    void shouldNotBeEqual2() {
        manager = templateManagerWithoutOneLocation();
        targetToFormat = anyPersonName();
        actual = manager.format(targetToFormat, Locale.GERMANY);
        assertEquals("Hans, M\00FCller", actual);
    }

    @Test
    void shouldNotBeEqual3() {
        manager = templateManagerWithoutLocation2();
        targetToFormat = anyPersonName();
        actual = manager.format(targetToFormat, Locale.GERMANY);
        assertNotEquals("Hans, M\00FCller", actual);
    }

    private static TemplateManager<PersonName> templateManagerWithoutLocation() {
        final var builder = new TemplateManagerBuilder<PersonName>();
        return builder.useAsDefault(getDeafultFormatter()).with(null).build();
    }

    private static TemplateManager<PersonName> templateManagerWithoutOneLocation() {
        final var map = new HashMap<Locale, TemplateFormatter<PersonName>>(0);
        map.put(Locale.GERMANY, getFormatterForGermany());
        final var builder = new TemplateManagerBuilder<PersonName>();
        return builder.useAsDefault(getDeafultFormatter()).with(map).build();
    }

    private static TemplateManager<PersonName> templateManagerWithoutLocation2() {
        final var map = new HashMap<Locale, TemplateFormatter<PersonName>>(0);
        map.put(null, null);
        final var builder = new TemplateManagerBuilder<PersonName>();
        return builder.useAsDefault(getDeafultFormatter()).with(map).build();
    }

}
