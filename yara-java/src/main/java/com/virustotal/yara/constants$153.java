// Generated by jextract

package com.virustotal.yara;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
final class constants$153 {

    // Suppresses default constructor, ensuring non-instantiability.
    private constants$153() {}
    static final FunctionDescriptor __fmaf$FUNC = FunctionDescriptor.of(Constants$root.C_FLOAT$LAYOUT,
        Constants$root.C_FLOAT$LAYOUT,
        Constants$root.C_FLOAT$LAYOUT,
        Constants$root.C_FLOAT$LAYOUT
    );
    static final MethodHandle __fmaf$MH = RuntimeHelper.downcallHandle(
        "__fmaf",
        constants$153.__fmaf$FUNC
    );
    static final FunctionDescriptor scalbf$FUNC = FunctionDescriptor.of(Constants$root.C_FLOAT$LAYOUT,
        Constants$root.C_FLOAT$LAYOUT,
        Constants$root.C_FLOAT$LAYOUT
    );
    static final MethodHandle scalbf$MH = RuntimeHelper.downcallHandle(
        "scalbf",
        constants$153.scalbf$FUNC
    );
    static final FunctionDescriptor __scalbf$FUNC = FunctionDescriptor.of(Constants$root.C_FLOAT$LAYOUT,
        Constants$root.C_FLOAT$LAYOUT,
        Constants$root.C_FLOAT$LAYOUT
    );
    static final MethodHandle __scalbf$MH = RuntimeHelper.downcallHandle(
        "__scalbf",
        constants$153.__scalbf$FUNC
    );
    static final OfInt signgam$LAYOUT = Constants$root.C_INT$LAYOUT;
    static final VarHandle signgam$VH = constants$153.signgam$LAYOUT.varHandle();
    static final MemorySegment signgam$SEGMENT = RuntimeHelper.lookupGlobalVariable("signgam", constants$153.signgam$LAYOUT);
    static final FunctionDescriptor yr_scanner_create$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle yr_scanner_create$MH = RuntimeHelper.downcallHandle(
        "yr_scanner_create",
        constants$153.yr_scanner_create$FUNC
    );
    static final FunctionDescriptor yr_scanner_destroy$FUNC = FunctionDescriptor.ofVoid(
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle yr_scanner_destroy$MH = RuntimeHelper.downcallHandle(
        "yr_scanner_destroy",
        constants$153.yr_scanner_destroy$FUNC
    );
}

