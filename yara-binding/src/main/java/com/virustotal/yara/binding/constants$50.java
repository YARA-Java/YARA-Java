// Generated by jextract

package com.virustotal.yara.binding;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
final class constants$50 {

    // Suppresses default constructor, ensuring non-instantiability.
    private constants$50() {}
    static final FunctionDescriptor toupper_l$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle toupper_l$MH = RuntimeHelper.downcallHandle(
        "toupper_l",
        constants$50.toupper_l$FUNC
    );
    static final FunctionDescriptor YR_STREAM_READ_FUNC$FUNC = FunctionDescriptor.of(Constants$root.C_LONG_LONG$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_LONG_LONG$LAYOUT,
        Constants$root.C_LONG_LONG$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle YR_STREAM_READ_FUNC$MH = RuntimeHelper.downcallHandle(
        constants$50.YR_STREAM_READ_FUNC$FUNC
    );
    static final FunctionDescriptor YR_STREAM_WRITE_FUNC$FUNC = FunctionDescriptor.of(Constants$root.C_LONG_LONG$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_LONG_LONG$LAYOUT,
        Constants$root.C_LONG_LONG$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle YR_STREAM_WRITE_FUNC$MH = RuntimeHelper.downcallHandle(
        constants$50.YR_STREAM_WRITE_FUNC$FUNC
    );
    static final FunctionDescriptor yr_stream_read$FUNC = FunctionDescriptor.of(Constants$root.C_LONG_LONG$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_LONG_LONG$LAYOUT,
        Constants$root.C_LONG_LONG$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle yr_stream_read$MH = RuntimeHelper.downcallHandle(
        "yr_stream_read",
        constants$50.yr_stream_read$FUNC
    );
}


