// Generated by jextract

package com.virustotal.yara.binding;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
final class constants$117 {

    // Suppresses default constructor, ensuring non-instantiability.
    private constants$117() {}
    static final FunctionDescriptor fmod$FUNC = FunctionDescriptor.of(Constants$root.C_DOUBLE$LAYOUT,
        Constants$root.C_DOUBLE$LAYOUT,
        Constants$root.C_DOUBLE$LAYOUT
    );
    static final MethodHandle fmod$MH = RuntimeHelper.downcallHandle(
        "fmod",
        constants$117.fmod$FUNC
    );
    static final FunctionDescriptor __fmod$FUNC = FunctionDescriptor.of(Constants$root.C_DOUBLE$LAYOUT,
        Constants$root.C_DOUBLE$LAYOUT,
        Constants$root.C_DOUBLE$LAYOUT
    );
    static final MethodHandle __fmod$MH = RuntimeHelper.downcallHandle(
        "__fmod",
        constants$117.__fmod$FUNC
    );
    static final FunctionDescriptor isinf$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_DOUBLE$LAYOUT
    );
    static final MethodHandle isinf$MH = RuntimeHelper.downcallHandle(
        "isinf",
        constants$117.isinf$FUNC
    );
    static final FunctionDescriptor finite$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_DOUBLE$LAYOUT
    );
    static final MethodHandle finite$MH = RuntimeHelper.downcallHandle(
        "finite",
        constants$117.finite$FUNC
    );
    static final FunctionDescriptor drem$FUNC = FunctionDescriptor.of(Constants$root.C_DOUBLE$LAYOUT,
        Constants$root.C_DOUBLE$LAYOUT,
        Constants$root.C_DOUBLE$LAYOUT
    );
    static final MethodHandle drem$MH = RuntimeHelper.downcallHandle(
        "drem",
        constants$117.drem$FUNC
    );
    static final FunctionDescriptor __drem$FUNC = FunctionDescriptor.of(Constants$root.C_DOUBLE$LAYOUT,
        Constants$root.C_DOUBLE$LAYOUT,
        Constants$root.C_DOUBLE$LAYOUT
    );
    static final MethodHandle __drem$MH = RuntimeHelper.downcallHandle(
        "__drem",
        constants$117.__drem$FUNC
    );
}


