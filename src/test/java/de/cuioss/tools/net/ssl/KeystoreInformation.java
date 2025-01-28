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
package de.cuioss.tools.net.ssl;

import lombok.experimental.UtilityClass;

import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Provide some constants for the testKeystore
 *
 * @author Oliver Wolff
 *
 */
@UtilityClass
public class KeystoreInformation {

    public static final String PASSWORD = "secret";

    public static final Path BASE = Paths.get("src", "test", "resources");

    public static final Path EMPTY_KEY_STORE = BASE.resolve("emptyKeystore.jks");

    public static final Path SINGLE_KEY_STORE = BASE.resolve("singleKeyKeystore.jks");

    public static final Path EMPTY_KEY_STORE_NO_PASSWORD = BASE.resolve("emptyKeystoreNoPassword.jks");

    public static final String SINGLE_KEY_NAME = "test";
}
