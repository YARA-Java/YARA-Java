// Generated by jextract

package com.virustotal.yara.binding;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
final class constants$33 {

    // Suppresses default constructor, ensuring non-instantiability.
    private constants$33() {}
    static final FunctionDescriptor memcpy$FUNC = FunctionDescriptor.of(Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_LONG_LONG$LAYOUT
    );
    static final MethodHandle memcpy$MH = RuntimeHelper.downcallHandle(
        "memcpy",
        constants$33.memcpy$FUNC
    );
    static final FunctionDescriptor memmove$FUNC = FunctionDescriptor.of(Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_LONG_LONG$LAYOUT
    );
    static final MethodHandle memmove$MH = RuntimeHelper.downcallHandle(
        "memmove",
        constants$33.memmove$FUNC
    );
    static final FunctionDescriptor memccpy$FUNC = FunctionDescriptor.of(Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_INT$LAYOUT,
        Constants$root.C_LONG_LONG$LAYOUT
    );
    static final MethodHandle memccpy$MH = RuntimeHelper.downcallHandle(
        "memccpy",
        constants$33.memccpy$FUNC
    );
    static final FunctionDescriptor memset$FUNC = FunctionDescriptor.of(Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_INT$LAYOUT,
        Constants$root.C_LONG_LONG$LAYOUT
    );
    static final MethodHandle memset$MH = RuntimeHelper.downcallHandle(
        "memset",
        constants$33.memset$FUNC
    );
    static final FunctionDescriptor memcmp$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_LONG_LONG$LAYOUT
    );
    static final MethodHandle memcmp$MH = RuntimeHelper.downcallHandle(
        "memcmp",
        constants$33.memcmp$FUNC
    );
    static final FunctionDescriptor __memcmpeq$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_LONG_LONG$LAYOUT
    );
    static final MethodHandle __memcmpeq$MH = RuntimeHelper.downcallHandle(
        "__memcmpeq",
        constants$33.__memcmpeq$FUNC
    );
}


