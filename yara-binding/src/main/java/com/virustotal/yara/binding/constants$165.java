// Generated by jextract

package com.virustotal.yara.binding;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
final class constants$165 {

    // Suppresses default constructor, ensuring non-instantiability.
    private constants$165() {}
    static final FunctionDescriptor YR_EXT_LOAD_FUNC$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_LONG_LONG$LAYOUT
    );
    static final MethodHandle YR_EXT_LOAD_FUNC$MH = RuntimeHelper.downcallHandle(
        constants$165.YR_EXT_LOAD_FUNC$FUNC
    );
    static final FunctionDescriptor YR_EXT_UNLOAD_FUNC$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle YR_EXT_UNLOAD_FUNC$MH = RuntimeHelper.downcallHandle(
        constants$165.YR_EXT_UNLOAD_FUNC$FUNC
    );
    static final FunctionDescriptor yr_modules_initialize$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT);
    static final MethodHandle yr_modules_initialize$MH = RuntimeHelper.downcallHandle(
        "yr_modules_initialize",
        constants$165.yr_modules_initialize$FUNC
    );
    static final FunctionDescriptor yr_modules_finalize$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT);
    static final MethodHandle yr_modules_finalize$MH = RuntimeHelper.downcallHandle(
        "yr_modules_finalize",
        constants$165.yr_modules_finalize$FUNC
    );
}


