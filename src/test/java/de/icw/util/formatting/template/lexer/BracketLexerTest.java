package de.icw.util.formatting.template.lexer;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import de.icw.util.formatting.support.PersonAddress;
import de.icw.util.formatting.support.PersonAddressGenerator;
import de.icw.util.formatting.template.lexer.BracketLexer.Brackets;
import de.icw.util.formatting.template.token.Token;
import de.icw.util.support.ObjectMethodsAsserts;
import de.icw.util.support.TypedGenerator;

class BracketLexerTest {

    private final TypedGenerator<PersonAddress> generator = new PersonAddressGenerator();

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

}
