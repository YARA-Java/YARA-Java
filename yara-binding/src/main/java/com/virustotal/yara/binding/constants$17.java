// Generated by jextract

package com.virustotal.yara.binding;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
final class constants$17 {

    // Suppresses default constructor, ensuring non-instantiability.
    private constants$17() {}
    static final FunctionDescriptor strtof$FUNC = FunctionDescriptor.of(Constants$root.C_FLOAT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle strtof$MH = RuntimeHelper.downcallHandle(
        "strtof",
        constants$17.strtof$FUNC
    );
    static final FunctionDescriptor strtol$FUNC = FunctionDescriptor.of(Constants$root.C_LONG_LONG$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_INT$LAYOUT
    );
    static final MethodHandle strtol$MH = RuntimeHelper.downcallHandle(
        "strtol",
        constants$17.strtol$FUNC
    );
    static final FunctionDescriptor strtoul$FUNC = FunctionDescriptor.of(Constants$root.C_LONG_LONG$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_INT$LAYOUT
    );
    static final MethodHandle strtoul$MH = RuntimeHelper.downcallHandle(
        "strtoul",
        constants$17.strtoul$FUNC
    );
    static final FunctionDescriptor strtoq$FUNC = FunctionDescriptor.of(Constants$root.C_LONG_LONG$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_INT$LAYOUT
    );
    static final MethodHandle strtoq$MH = RuntimeHelper.downcallHandle(
        "strtoq",
        constants$17.strtoq$FUNC
    );
    static final FunctionDescriptor strtouq$FUNC = FunctionDescriptor.of(Constants$root.C_LONG_LONG$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_INT$LAYOUT
    );
    static final MethodHandle strtouq$MH = RuntimeHelper.downcallHandle(
        "strtouq",
        constants$17.strtouq$FUNC
    );
    static final FunctionDescriptor strtoll$FUNC = FunctionDescriptor.of(Constants$root.C_LONG_LONG$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_INT$LAYOUT
    );
    static final MethodHandle strtoll$MH = RuntimeHelper.downcallHandle(
        "strtoll",
        constants$17.strtoll$FUNC
    );
}


