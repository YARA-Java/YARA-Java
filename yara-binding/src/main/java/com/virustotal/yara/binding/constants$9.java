// Generated by jextract

package com.virustotal.yara.binding;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
final class constants$9 {

    // Suppresses default constructor, ensuring non-instantiability.
    private constants$9() {}
    static final FunctionDescriptor putc_unlocked$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle putc_unlocked$MH = RuntimeHelper.downcallHandle(
        "putc_unlocked",
        constants$9.putc_unlocked$FUNC
    );
    static final FunctionDescriptor putchar_unlocked$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_INT$LAYOUT
    );
    static final MethodHandle putchar_unlocked$MH = RuntimeHelper.downcallHandle(
        "putchar_unlocked",
        constants$9.putchar_unlocked$FUNC
    );
    static final FunctionDescriptor getw$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle getw$MH = RuntimeHelper.downcallHandle(
        "getw",
        constants$9.getw$FUNC
    );
    static final FunctionDescriptor putw$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle putw$MH = RuntimeHelper.downcallHandle(
        "putw",
        constants$9.putw$FUNC
    );
    static final FunctionDescriptor fgets$FUNC = FunctionDescriptor.of(Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle fgets$MH = RuntimeHelper.downcallHandle(
        "fgets",
        constants$9.fgets$FUNC
    );
    static final FunctionDescriptor __getdelim$FUNC = FunctionDescriptor.of(Constants$root.C_LONG_LONG$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle __getdelim$MH = RuntimeHelper.downcallHandle(
        "__getdelim",
        constants$9.__getdelim$FUNC
    );
}


