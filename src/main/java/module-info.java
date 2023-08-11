module de.cuioss.java.tools {
    requires static lombok;
    requires java.desktop;
    requires java.logging;

    exports de.cuioss.tools.base;
    exports de.cuioss.tools.codec;
    exports de.cuioss.tools.collect;
    exports de.cuioss.tools.concurrent;
    exports de.cuioss.tools.formatting;
    exports de.cuioss.tools.formatting.template;
    exports de.cuioss.tools.formatting.template.lexer;
    exports de.cuioss.tools.formatting.template.token;
    exports de.cuioss.tools.io;
    exports de.cuioss.tools.lang;
    exports de.cuioss.tools.net;
    exports de.cuioss.tools.net.ssl;
    exports de.cuioss.tools.property;
    exports de.cuioss.tools.reflect;
    exports de.cuioss.tools.string;
}