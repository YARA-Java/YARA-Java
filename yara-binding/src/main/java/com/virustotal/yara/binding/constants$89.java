// Generated by jextract

package com.virustotal.yara.binding;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
final class constants$89 {

    // Suppresses default constructor, ensuring non-instantiability.
    private constants$89() {}
    static final FunctionDescriptor yr_notebook_alloc$FUNC = FunctionDescriptor.of(Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_LONG_LONG$LAYOUT
    );
    static final MethodHandle yr_notebook_alloc$MH = RuntimeHelper.downcallHandle(
        "yr_notebook_alloc",
        constants$89.yr_notebook_alloc$FUNC
    );
    static final FunctionDescriptor YR_MEMORY_BLOCK_FETCH_DATA_FUNC$FUNC = FunctionDescriptor.of(Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle YR_MEMORY_BLOCK_FETCH_DATA_FUNC$MH = RuntimeHelper.downcallHandle(
        constants$89.YR_MEMORY_BLOCK_FETCH_DATA_FUNC$FUNC
    );
    static final FunctionDescriptor YR_MEMORY_BLOCK_ITERATOR_FUNC$FUNC = FunctionDescriptor.of(Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle YR_MEMORY_BLOCK_ITERATOR_FUNC$MH = RuntimeHelper.downcallHandle(
        constants$89.YR_MEMORY_BLOCK_ITERATOR_FUNC$FUNC
    );
    static final FunctionDescriptor YR_MEMORY_BLOCK_ITERATOR_SIZE_FUNC$FUNC = FunctionDescriptor.of(Constants$root.C_LONG_LONG$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
}


