// Generated by jextract

package com.virustotal.yara.binding;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
final class constants$90 {

    // Suppresses default constructor, ensuring non-instantiability.
    private constants$90() {}
    static final FunctionDescriptor YR_MEMORY_BLOCK_ITERATOR_SIZE_FUNC$FUNC = FunctionDescriptor.of(Constants$root.C_LONG_LONG$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle YR_MEMORY_BLOCK_ITERATOR_SIZE_FUNC$MH = RuntimeHelper.downcallHandle(
        constants$90.YR_MEMORY_BLOCK_ITERATOR_SIZE_FUNC$FUNC
    );
    static final FunctionDescriptor YR_CALLBACK_FUNC$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle YR_CALLBACK_FUNC$MH = RuntimeHelper.downcallHandle(
        constants$90.YR_CALLBACK_FUNC$FUNC
    );
    static final FunctionDescriptor YR_MODULE_FUNC$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle YR_MODULE_FUNC$MH = RuntimeHelper.downcallHandle(
        constants$90.YR_MODULE_FUNC$FUNC
    );
    static final FunctionDescriptor YR_ITERATOR_NEXT_FUNC$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
}


