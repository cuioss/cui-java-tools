package io.cui.util.formatting.template.lexer;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;

import org.junit.jupiter.api.Test;

import io.cui.util.formatting.template.FormatterSupport;
import io.cui.util.formatting.template.token.Token;

class LexerTest {

    @Test
    void shouldFailWithOnMissingSource() {
        assertThrows(NullPointerException.class, () -> new TestImplLexer<>(null));
    }

    @Test
    void shouldFailOnMissingAttributes() {
        final WrongFormatterSupportImplWithMissingAttributeList source =
            new WrongFormatterSupportImplWithMissingAttributeList();

        assertThrows(NullPointerException.class, () -> new TestImplLexer<>(source));
    }

    @Test
    void shouldFailOnEmptyAttributes() {
        final WrongFormatterSupportImplWithEmptyAttributeList source =
            new WrongFormatterSupportImplWithEmptyAttributeList();
        assertThrows(IllegalArgumentException.class, () -> new TestImplLexer<>(source));
    }

    class TestImplLexer<T extends FormatterSupport> extends Lexer<T> {

        private static final long serialVersionUID = -7653785743419231265L;

        public TestImplLexer(final T source) {
            super(source);
        }

        @Override
        public List<Token> scan(final String input) {
            return null;
        }

    }

}
