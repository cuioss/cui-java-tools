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

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;

import org.junit.jupiter.api.Test;

import de.cuioss.tools.formatting.template.FormatterSupport;
import de.cuioss.tools.formatting.template.token.Token;

class LexerTest {

    @Test
    void shouldFailWithOnMissingSource() {
        assertThrows(NullPointerException.class, () -> new TestImplLexer<>(null));
    }

    @Test
    void shouldFailOnMissingAttributes() {
        final var source = new WrongFormatterSupportImplWithMissingAttributeList();

        assertThrows(NullPointerException.class, () -> new TestImplLexer<>(source));
    }

    @Test
    void shouldFailOnEmptyAttributes() {
        final var source = new WrongFormatterSupportImplWithEmptyAttributeList();
        assertThrows(IllegalArgumentException.class, () -> new TestImplLexer<>(source));
    }

    static class TestImplLexer<T extends FormatterSupport> extends Lexer<T> {

        private static final long serialVersionUID = -7653785743419231265L;

        public TestImplLexer(final T source) {
            super(source);
        }

        @Override
        public List<Token> scan(final String input) {
            return null;
        }

    }

    @Test
    void shouldFailwithInvalidSourceType() {
        var builder = LexerBuilder.useSimpleElWithSquaredBrackets();
        assertThrows(IllegalStateException.class, () -> builder.build(NoPublicZeroArgConstructor.class));
    }

}
