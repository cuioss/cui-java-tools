package io.cui.util.formatting.template.lexer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import io.cui.util.formatting.support.PersonAddress;
import io.cui.util.formatting.support.PersonAddressGenerator;
import io.cui.util.formatting.support.PersonName;
import io.cui.util.formatting.template.Validator;
import io.cui.util.formatting.template.WrongDataObject;
import io.cui.util.formatting.template.lexer.BracketLexer.Brackets;
import io.cui.util.formatting.template.lexer.Lexer.ExpressionLanguage;
import io.cui.util.formatting.template.token.Token;
import io.cui.util.support.ObjectMethodsAsserts;
import io.cui.util.support.TypedGenerator;

class BracketLexerTest {

    private final TypedGenerator<PersonAddress> generator = new PersonAddressGenerator();

    private static final String PERSON_NAME_FORMAT = "[familyName, ][givenName ][middleName]";

    private static final String PERSON_NAME_FORMAT_WITH_STATIC_PREFIX =
        "StaticPrefix: [familyName, ][givenName ][middleName] StaticSuffix";

    private static final String PERSON_NAME_FORMAT_ANGLE_BRACKET =
        "<familyName, ><givenName ><middleName>";

    private static final String PERSON_NAME_FORMAT_CURLY_BRACKTETS = "{familyName, }{givenName }{middleName}";

    @Test
    void testScan() {
        final List<Token> result = new ArrayList<>();
        final Lexer<PersonAddress> lexer =
            new BracketLexer<>(generator.next(), Brackets.CURLY_BRACKETS);
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
        assertThrows(IllegalArgumentException.class,
                () -> Validator.validateTemplate("[givenName", PersonName.class));
    }

    @Test
    void shouldPassValidationWithStaticPrefix() {
        Validator.validateTemplate(PERSON_NAME_FORMAT_WITH_STATIC_PREFIX, PersonName.class);
    }

    @Test
    void shouldPassValidationForAngleBrackets() {
        Validator.validateTemplate(PERSON_NAME_FORMAT_ANGLE_BRACKET,
                LexerBuilder.withExpressionLanguage(ExpressionLanguage.SIMPLE_ANGLE_BRACKET)
                        .build(PersonName.class));
    }

    @Test
    void shouldPassValidationForCurlyBrackets() {
        Validator.validateTemplate(PERSON_NAME_FORMAT_CURLY_BRACKTETS,
                LexerBuilder.withExpressionLanguage(ExpressionLanguage.SIMPLE_CURLY_BRACKETS)
                        .build(PersonName.class));
    }

    @Test
    void shouldFailOnValidation() {
        assertThrows(IllegalArgumentException.class,
                () -> Validator.validateTemplate(PERSON_NAME_FORMAT, WrongDataObject.class));
    }

    @Test
    void shouldFailOnValidationByLexer() {
        final Lexer<WrongDataObject> lexer =
            LexerBuilder.withExpressionLanguage(ExpressionLanguage.SIMPLE_ANGLE_BRACKET)
                    .build(WrongDataObject.class);
        assertThrows(IllegalArgumentException.class,
                () -> Validator.validateTemplate(PERSON_NAME_FORMAT_ANGLE_BRACKET, lexer));
    }
}
