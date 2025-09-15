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
module de.cuioss.java.tools {
    requires static lombok;
    requires static org.jspecify;
    requires transitive java.desktop;
    requires transitive java.logging;
    requires java.net.http;

    exports de.cuioss.tools.base;
    exports de.cuioss.tools.codec;
    exports de.cuioss.tools.collect;
    exports de.cuioss.tools.concurrent;
    exports de.cuioss.tools.formatting;
    exports de.cuioss.tools.formatting.template;
    exports de.cuioss.tools.formatting.template.lexer;
    exports de.cuioss.tools.formatting.template.token;
    exports de.cuioss.http.client.handler;
    exports de.cuioss.tools.io;
    exports de.cuioss.tools.lang;
    exports de.cuioss.tools.logging;
    exports de.cuioss.tools.net;
    exports de.cuioss.tools.net.ssl;
    exports de.cuioss.tools.property;
    exports de.cuioss.tools.reflect;
    exports de.cuioss.http.security.core;
    exports de.cuioss.http.security.config;
    exports de.cuioss.http.security.data;
    exports de.cuioss.http.security.exceptions;
    exports de.cuioss.tools.string;
}