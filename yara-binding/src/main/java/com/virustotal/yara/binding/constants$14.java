// Generated by jextract

package com.virustotal.yara.binding;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
final class constants$14 {

    // Suppresses default constructor, ensuring non-instantiability.
    private constants$14() {}
    static final FunctionDescriptor fileno_unlocked$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle fileno_unlocked$MH = RuntimeHelper.downcallHandle(
        "fileno_unlocked",
        constants$14.fileno_unlocked$FUNC
    );
    static final FunctionDescriptor pclose$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle pclose$MH = RuntimeHelper.downcallHandle(
        "pclose",
        constants$14.pclose$FUNC
    );
    static final FunctionDescriptor popen$FUNC = FunctionDescriptor.of(Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle popen$MH = RuntimeHelper.downcallHandle(
        "popen",
        constants$14.popen$FUNC
    );
    static final FunctionDescriptor ctermid$FUNC = FunctionDescriptor.of(Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle ctermid$MH = RuntimeHelper.downcallHandle(
        "ctermid",
        constants$14.ctermid$FUNC
    );
    static final FunctionDescriptor flockfile$FUNC = FunctionDescriptor.ofVoid(
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle flockfile$MH = RuntimeHelper.downcallHandle(
        "flockfile",
        constants$14.flockfile$FUNC
    );
    static final FunctionDescriptor ftrylockfile$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle ftrylockfile$MH = RuntimeHelper.downcallHandle(
        "ftrylockfile",
        constants$14.ftrylockfile$FUNC
    );
}


