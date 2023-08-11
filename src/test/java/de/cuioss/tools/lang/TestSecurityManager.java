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
package de.cuioss.tools.lang;

import static de.cuioss.tools.collect.CollectionLiterals.immutableList;

import java.io.FilePermission;
import java.lang.reflect.AccessibleObject;
import java.security.AccessControlException;
import java.security.Permission;
import java.util.List;
import java.util.PropertyPermission;
import java.util.logging.LogManager;

import lombok.Getter;
import lombok.Setter;

class TestSecurityManager extends SecurityManager {

    @Getter
    @Setter
    private boolean allowSecuritySupport = true;

    @Override
    public void checkPermission(Permission perm) {

        if (allowSecuritySupport || perm instanceof FilePermission || perm instanceof PropertyPermission) {
            // Not interested in
            return;
        }
        List<Class<?>> callStack = immutableList(getClassContext());

        Class<?> filter = callStack.get(1);
        List<Class<?>> ignoreTypes = immutableList(LogManager.class, Class.class, AccessibleObject.class);

        if (ignoreTypes.contains(filter)) {
            // Not interested in
            return;
        }
        for (Class<?> clazz : callStack) {
            if (SecuritySupport.class.equals(clazz)) {
                System.out.println(callStack);
                throw new AccessControlException("Not allowed by configuration" + filter);
            }
        }

    }
}
