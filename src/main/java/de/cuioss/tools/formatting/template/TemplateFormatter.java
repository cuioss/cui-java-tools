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
package de.cuioss.tools.formatting.template;

import java.io.Serializable;

/**
 * The formatter should be able to convert complex type based on
 * {@link FormatterSupport} into text by using a defined template.
 * <p>
 * See {@link de.cuioss.tools.formatting} for details.
 *
 * @param <T> bounded type based on {@link FormatterSupport}
 *
 * @author Eugen Fischer
 */
public interface TemplateFormatter<T extends FormatterSupport> extends Serializable {

    /**
     * Execute transformation based on configured template and values for the
     * defined placeholders. Missing values should get ignored.
     *
     * @param reference must not be {@code null}
     *
     * @return formatted text
     * @throws NullPointerException if reference is missing
     */
    String format(final T reference);

}
