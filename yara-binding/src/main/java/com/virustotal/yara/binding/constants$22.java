// Generated by jextract

package com.virustotal.yara.binding;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
final class constants$22 {

    // Suppresses default constructor, ensuring non-instantiability.
    private constants$22() {}
    static final FunctionDescriptor lcong48$FUNC = FunctionDescriptor.ofVoid(
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle lcong48$MH = RuntimeHelper.downcallHandle(
        "lcong48",
        constants$22.lcong48$FUNC
    );
    static final FunctionDescriptor drand48_r$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle drand48_r$MH = RuntimeHelper.downcallHandle(
        "drand48_r",
        constants$22.drand48_r$FUNC
    );
    static final FunctionDescriptor erand48_r$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle erand48_r$MH = RuntimeHelper.downcallHandle(
        "erand48_r",
        constants$22.erand48_r$FUNC
    );
    static final FunctionDescriptor lrand48_r$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle lrand48_r$MH = RuntimeHelper.downcallHandle(
        "lrand48_r",
        constants$22.lrand48_r$FUNC
    );
    static final FunctionDescriptor nrand48_r$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle nrand48_r$MH = RuntimeHelper.downcallHandle(
        "nrand48_r",
        constants$22.nrand48_r$FUNC
    );
    static final FunctionDescriptor mrand48_r$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle mrand48_r$MH = RuntimeHelper.downcallHandle(
        "mrand48_r",
        constants$22.mrand48_r$FUNC
    );
}


