// Generated by jextract

package com.virustotal.yara.binding;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
final class constants$76 {

    // Suppresses default constructor, ensuring non-instantiability.
    private constants$76() {}
    static final FunctionDescriptor pthread_mutex_setprioceiling$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle pthread_mutex_setprioceiling$MH = RuntimeHelper.downcallHandle(
        "pthread_mutex_setprioceiling",
        constants$76.pthread_mutex_setprioceiling$FUNC
    );
    static final FunctionDescriptor pthread_mutex_consistent$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle pthread_mutex_consistent$MH = RuntimeHelper.downcallHandle(
        "pthread_mutex_consistent",
        constants$76.pthread_mutex_consistent$FUNC
    );
    static final FunctionDescriptor pthread_mutexattr_init$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle pthread_mutexattr_init$MH = RuntimeHelper.downcallHandle(
        "pthread_mutexattr_init",
        constants$76.pthread_mutexattr_init$FUNC
    );
    static final FunctionDescriptor pthread_mutexattr_destroy$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle pthread_mutexattr_destroy$MH = RuntimeHelper.downcallHandle(
        "pthread_mutexattr_destroy",
        constants$76.pthread_mutexattr_destroy$FUNC
    );
    static final FunctionDescriptor pthread_mutexattr_getpshared$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle pthread_mutexattr_getpshared$MH = RuntimeHelper.downcallHandle(
        "pthread_mutexattr_getpshared",
        constants$76.pthread_mutexattr_getpshared$FUNC
    );
    static final FunctionDescriptor pthread_mutexattr_setpshared$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_INT$LAYOUT
    );
    static final MethodHandle pthread_mutexattr_setpshared$MH = RuntimeHelper.downcallHandle(
        "pthread_mutexattr_setpshared",
        constants$76.pthread_mutexattr_setpshared$FUNC
    );
}


