// Generated by jextract

package com.virustotal.yara.binding;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
final class constants$4 {

    // Suppresses default constructor, ensuring non-instantiability.
    private constants$4() {}
    static final FunctionDescriptor setbuf$FUNC = FunctionDescriptor.ofVoid(
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle setbuf$MH = RuntimeHelper.downcallHandle(
        "setbuf",
        constants$4.setbuf$FUNC
    );
    static final FunctionDescriptor setvbuf$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_INT$LAYOUT,
        Constants$root.C_LONG_LONG$LAYOUT
    );
    static final MethodHandle setvbuf$MH = RuntimeHelper.downcallHandle(
        "setvbuf",
        constants$4.setvbuf$FUNC
    );
    static final FunctionDescriptor setbuffer$FUNC = FunctionDescriptor.ofVoid(
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_LONG_LONG$LAYOUT
    );
    static final MethodHandle setbuffer$MH = RuntimeHelper.downcallHandle(
        "setbuffer",
        constants$4.setbuffer$FUNC
    );
    static final FunctionDescriptor setlinebuf$FUNC = FunctionDescriptor.ofVoid(
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle setlinebuf$MH = RuntimeHelper.downcallHandle(
        "setlinebuf",
        constants$4.setlinebuf$FUNC
    );
    static final FunctionDescriptor fprintf$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle fprintf$MH = RuntimeHelper.downcallHandleVariadic(
        "fprintf",
        constants$4.fprintf$FUNC
    );
    static final FunctionDescriptor printf$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle printf$MH = RuntimeHelper.downcallHandleVariadic(
        "printf",
        constants$4.printf$FUNC
    );
}

