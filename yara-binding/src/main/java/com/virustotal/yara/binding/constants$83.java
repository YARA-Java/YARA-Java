// Generated by jextract

package com.virustotal.yara.binding;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
final class constants$83 {

    // Suppresses default constructor, ensuring non-instantiability.
    private constants$83() {}
    static final FunctionDescriptor pthread_spin_destroy$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle pthread_spin_destroy$MH = RuntimeHelper.downcallHandle(
        "pthread_spin_destroy",
        constants$83.pthread_spin_destroy$FUNC
    );
    static final FunctionDescriptor pthread_spin_lock$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle pthread_spin_lock$MH = RuntimeHelper.downcallHandle(
        "pthread_spin_lock",
        constants$83.pthread_spin_lock$FUNC
    );
    static final FunctionDescriptor pthread_spin_trylock$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle pthread_spin_trylock$MH = RuntimeHelper.downcallHandle(
        "pthread_spin_trylock",
        constants$83.pthread_spin_trylock$FUNC
    );
    static final FunctionDescriptor pthread_spin_unlock$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle pthread_spin_unlock$MH = RuntimeHelper.downcallHandle(
        "pthread_spin_unlock",
        constants$83.pthread_spin_unlock$FUNC
    );
    static final FunctionDescriptor pthread_barrier_init$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_INT$LAYOUT
    );
    static final MethodHandle pthread_barrier_init$MH = RuntimeHelper.downcallHandle(
        "pthread_barrier_init",
        constants$83.pthread_barrier_init$FUNC
    );
    static final FunctionDescriptor pthread_barrier_destroy$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle pthread_barrier_destroy$MH = RuntimeHelper.downcallHandle(
        "pthread_barrier_destroy",
        constants$83.pthread_barrier_destroy$FUNC
    );
}


