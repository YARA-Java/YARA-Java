// Generated by jextract

package com.virustotal.yara.binding;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.lang.foreign.*;
import static java.lang.foreign.ValueLayout.*;
final class constants$74 {

    // Suppresses default constructor, ensuring non-instantiability.
    private constants$74() {}
    static final FunctionDescriptor pthread_cancel$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_LONG_LONG$LAYOUT
    );
    static final MethodHandle pthread_cancel$MH = RuntimeHelper.downcallHandle(
        "pthread_cancel",
        constants$74.pthread_cancel$FUNC
    );
    static final FunctionDescriptor pthread_testcancel$FUNC = FunctionDescriptor.ofVoid();
    static final MethodHandle pthread_testcancel$MH = RuntimeHelper.downcallHandle(
        "pthread_testcancel",
        constants$74.pthread_testcancel$FUNC
    );
    static final FunctionDescriptor __pthread_register_cancel$FUNC = FunctionDescriptor.ofVoid(
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle __pthread_register_cancel$MH = RuntimeHelper.downcallHandle(
        "__pthread_register_cancel",
        constants$74.__pthread_register_cancel$FUNC
    );
    static final FunctionDescriptor __pthread_unregister_cancel$FUNC = FunctionDescriptor.ofVoid(
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle __pthread_unregister_cancel$MH = RuntimeHelper.downcallHandle(
        "__pthread_unregister_cancel",
        constants$74.__pthread_unregister_cancel$FUNC
    );
    static final FunctionDescriptor __pthread_unwind_next$FUNC = FunctionDescriptor.ofVoid(
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle __pthread_unwind_next$MH = RuntimeHelper.downcallHandle(
        "__pthread_unwind_next",
        constants$74.__pthread_unwind_next$FUNC
    );
    static final FunctionDescriptor pthread_mutex_init$FUNC = FunctionDescriptor.of(Constants$root.C_INT$LAYOUT,
        Constants$root.C_POINTER$LAYOUT,
        Constants$root.C_POINTER$LAYOUT
    );
    static final MethodHandle pthread_mutex_init$MH = RuntimeHelper.downcallHandle(
        "pthread_mutex_init",
        constants$74.pthread_mutex_init$FUNC
    );
}


