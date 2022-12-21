package io.cui.tools.lang;

import static io.cui.tools.collect.CollectionLiterals.immutableList;

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
