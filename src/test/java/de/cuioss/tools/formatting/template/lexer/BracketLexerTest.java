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
package de.cuioss.tools.formatting.template.lexer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import de.cuioss.tools.formatting.support.PersonAddress;
import de.cuioss.tools.formatting.support.PersonAddressGenerator;
import de.cuioss.tools.formatting.support.PersonName;
import de.cuioss.tools.formatting.template.Validator;
import de.cuioss.tools.formatting.template.WrongDataObject;
import de.cuioss.tools.formatting.template.lexer.BracketLexer.Brackets;
import de.cuioss.tools.formatting.template.lexer.Lexer.ExpressionLanguage;
import de.cuioss.tools.formatting.template.token.Token;
import de.cuioss.tools.support.ObjectMethodsAsserts;
import de.cuioss.tools.support.TypedGenerator;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

class BracketLexerTest {

    private final TypedGenerator<PersonAddress> generator = new PersonAddressGenerator();

    private static final String PERSON_NAME_FORMAT = "[familyName, ][givenName ][middleName]";

    private static final String PERSON_NAME_FORMAT_WITH_STATIC_PREFIX = "StaticPrefix: [familyName, ][givenName ][middleName] StaticSuffix";

    private static final String PERSON_NAME_FORMAT_ANGLE_BRACKET = "<familyName, ><givenName ><middleName>";

    private static final String PERSON_NAME_FORMAT_CURLY_BRACKTETS = "{familyName, }{givenName }{middleName}";

    @Test
    void scan() {
        final List<Token> result = new ArrayList<>();
        final Lexer<PersonAddress> lexer = new BracketLexer<>(generator.next(), Brackets.CURLY_BRACKETS);
        result.addAll(lexer.scan(null));
        assertEquals(0, result.size());
    }

    @Test
    void shouldImplementObjectContracts() {
        ObjectMethodsAsserts.assertNiceObject(new BracketLexer<>(generator.next(), Brackets.CURLY_BRACKETS));
    }

    @Test
    void shouldPassValidation() {
        Validator.validateTemplate(PERSON_NAME_FORMAT, PersonName.class);
    }

    @Test
    void shouldDetectUnbalancedTemplate() {
        assertThrows(IllegalArgumentException.class, () -> Validator.validateTemplate("[givenName", PersonName.class));
    }

    @Test
    void shouldPassValidationWithStaticPrefix() {
        Validator.validateTemplate(PERSON_NAME_FORMAT_WITH_STATIC_PREFIX, PersonName.class);
    }

    @Test
    void shouldPassValidationForAngleBrackets() {
        Validator.validateTemplate(PERSON_NAME_FORMAT_ANGLE_BRACKET,
                LexerBuilder.withExpressionLanguage(ExpressionLanguage.SIMPLE_ANGLE_BRACKET).build(PersonName.class));
    }

    @Test
    void shouldPassValidationForCurlyBrackets() {
        Validator.validateTemplate(PERSON_NAME_FORMAT_CURLY_BRACKTETS,
                LexerBuilder.withExpressionLanguage(ExpressionLanguage.SIMPLE_CURLY_BRACKETS).build(PersonName.class));
    }

    @Test
    void shouldFailOnValidation() {
        assertThrows(IllegalArgumentException.class,
                () -> Validator.validateTemplate(PERSON_NAME_FORMAT, WrongDataObject.class));
    }

    @Test
    void shouldFailOnValidationByLexer() {
        final Lexer<WrongDataObject> lexer = LexerBuilder
                .withExpressionLanguage(ExpressionLanguage.SIMPLE_ANGLE_BRACKET).build(WrongDataObject.class);
        assertThrows(IllegalArgumentException.class,
                () -> Validator.validateTemplate(PERSON_NAME_FORMAT_ANGLE_BRACKET, lexer));
    }
}
