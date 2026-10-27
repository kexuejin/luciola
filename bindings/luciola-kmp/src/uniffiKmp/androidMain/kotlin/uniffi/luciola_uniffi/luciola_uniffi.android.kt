

@file:Suppress("RemoveRedundantBackticks")

package uniffi.luciola_uniffi

// Common helper code.
//
// Ideally this would live in a separate .kt file where it can be unittested etc
// in isolation, and perhaps even published as a re-useable package.
//
// However, it's important that the details of how this helper code works (e.g. the
// way that different builtin types are passed across the FFI) exactly match what's
// expected by the Rust code on the other side of the interface. In practice right
// now that means coming from the exact some version of `uniffi` that was used to
// compile the Rust component. The easiest way to ensure this is to bundle the Kotlin
// helpers directly inline like we're doing here.

import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Structure
import android.os.Build
import androidx.annotation.RequiresApi


internal typealias Pointer = com.sun.jna.Pointer
internal val NullPointer: Pointer? = com.sun.jna.Pointer.NULL
internal fun Pointer.toLong(): Long = Pointer.nativeValue(this)
internal fun kotlin.Long.toPointer() = com.sun.jna.Pointer(this)


@kotlin.jvm.JvmInline
public value class ByteBuffer(private val inner: java.nio.ByteBuffer) {
    init {
        inner.order(java.nio.ByteOrder.BIG_ENDIAN)
    }

    public fun internal(): java.nio.ByteBuffer = inner

    public fun limit(): Int = inner.limit()

    public fun position(): Int = inner.position()

    public fun hasRemaining(): Boolean = inner.hasRemaining()

    public fun get(): Byte = inner.get()

    public fun get(bytesToRead: Int): ByteArray = ByteArray(bytesToRead).apply(inner::get)

    public fun getShort(): Short = inner.getShort()

    public fun getInt(): Int = inner.getInt()

    public fun getLong(): Long = inner.getLong()

    public fun getFloat(): Float = inner.getFloat()

    public fun getDouble(): Double = inner.getDouble()

    public fun put(value: Byte) {
        inner.put(value)
    }

    public fun put(src: ByteArray) {
        inner.put(src)
    }

    public fun putShort(value: Short) {
        inner.putShort(value)
    }

    public fun putInt(value: Int) {
        inner.putInt(value)
    }

    public fun putLong(value: Long) {
        inner.putLong(value)
    }

    public fun putFloat(value: Float) {
        inner.putFloat(value)
    }

    public fun putDouble(value: Double) {
        inner.putDouble(value)
    }
}
public fun RustBuffer.setValue(array: RustBufferByValue) {
    this.data = array.data
    this.len = array.len
    this.capacity = array.capacity
}

internal object RustBufferHelper {
    internal fun allocValue(size: ULong = 0UL): RustBufferByValue = uniffiRustCall { status ->
        // Note: need to convert the size to a `Long` value to make this work with JVM.
        UniffiLib.ffi_luciola_uniffi_rustbuffer_alloc(size.toLong(), status)
    }.also {
        if(it.data == null) {
            throw RuntimeException("RustBuffer.alloc() returned null data pointer (size=${size})")
        }
    }

    internal fun free(buf: RustBufferByValue) = uniffiRustCall { status ->
        UniffiLib.ffi_luciola_uniffi_rustbuffer_free(buf, status)
    }
}

@Structure.FieldOrder("capacity", "len", "data")
public open class RustBufferStruct(
    // Note: `capacity` and `len` are actually `ULong` values, but JVM only supports signed values.
    // When dealing with these fields, make sure to call `toULong()`.
    @JvmField public var capacity: Long,
    @JvmField public var len: Long,
    @JvmField public var data: Pointer?,
) : Structure() {
    public constructor(): this(0.toLong(), 0.toLong(), null)

    public class ByValue(
        capacity: Long,
        len: Long,
        data: Pointer?,
    ): RustBuffer(capacity, len, data), Structure.ByValue {
        public constructor(): this(0.toLong(), 0.toLong(), null)
    }

    /**
     * The equivalent of the `*mut RustBuffer` type.
     * Required for callbacks taking in an out pointer.
     *
     * Size is the sum of all values in the struct.
     */
    public class ByReference(
        capacity: Long,
        len: Long,
        data: Pointer?,
    ): RustBuffer(capacity, len, data), Structure.ByReference {
        public constructor(): this(0.toLong(), 0.toLong(), null)
    }
}

public typealias RustBuffer = RustBufferStruct
public typealias RustBufferByValue = RustBufferStruct.ByValue

internal fun RustBuffer.asByteBuffer(): ByteBuffer? {
    require(this.len <= Int.MAX_VALUE) {
        val length = this.len
        "cannot handle RustBuffer longer than Int.MAX_VALUE bytes: length is $length"
    }
    return ByteBuffer(data?.getByteBuffer(0L, this.len) ?: return null)
}

internal fun RustBufferByValue.asByteBuffer(): ByteBuffer? {
    require(this.len <= Int.MAX_VALUE) {
        val length = this.len
        "cannot handle RustBuffer longer than Int.MAX_VALUE bytes: length is $length"
    }
    return ByteBuffer(data?.getByteBuffer(0L, this.len) ?: return null)
}

// This is a helper for safely passing byte references into the rust code.
// It's not actually used at the moment, because there aren't many things that you
// can take a direct pointer to in the JVM, and if we're going to copy something
// then we might as well copy it into a `RustBuffer`. But it's here for API
// completeness.

@Structure.FieldOrder("len", "data")
internal open class ForeignBytesStruct : Structure() {
    @JvmField var len: Int = 0
    @JvmField var data: Pointer? = null

    internal class ByValue : ForeignBytes(), Structure.ByValue
}
internal typealias ForeignBytes = ForeignBytesStruct
internal typealias ForeignBytesByValue = ForeignBytesStruct.ByValue

public interface FfiConverter<KotlinType, FfiType> {
    // Convert an FFI type to a Kotlin type
    public fun lift(value: FfiType): KotlinType

    // Convert an Kotlin type to an FFI type
    public fun lower(value: KotlinType): FfiType

    // Read a Kotlin type from a `ByteBuffer`
    public fun read(buf: ByteBuffer): KotlinType

    // Calculate bytes to allocate when creating a `RustBuffer`
    //
    // This must return at least as many bytes as the write() function will
    // write. It can return more bytes than needed, for example when writing
    // Strings we can't know the exact bytes needed until we the UTF-8
    // encoding, so we pessimistically allocate the largest size possible (3
    // bytes per codepoint).  Allocating extra bytes is not really a big deal
    // because the `RustBuffer` is short-lived.
    public fun allocationSize(value: KotlinType): ULong

    // Write a Kotlin type to a `ByteBuffer`
    public fun write(value: KotlinType, buf: ByteBuffer)

    // Lower a value into a `RustBuffer`
    //
    // This method lowers a value into a `RustBuffer` rather than the normal
    // FfiType.  It's used by the callback interface code.  Callback interface
    // returns are always serialized into a `RustBuffer` regardless of their
    // normal FFI type.
    public fun lowerIntoRustBuffer(value: KotlinType): RustBufferByValue {
        val rbuf = RustBufferHelper.allocValue(allocationSize(value))
        val bbuf = rbuf.asByteBuffer()!!
        write(value, bbuf)
        return RustBufferByValue(
            capacity = rbuf.capacity,
            len = bbuf.position().toLong(),
            data = rbuf.data,
        )
    }

    // Lift a value from a `RustBuffer`.
    //
    // This here mostly because of the symmetry with `lowerIntoRustBuffer()`.
    // It's currently only used by the `FfiConverterRustBuffer` class below.
    public fun liftFromRustBuffer(rbuf: RustBufferByValue): KotlinType {
        val byteBuf = rbuf.asByteBuffer()!!
        try {
           val item = read(byteBuf)
           if (byteBuf.hasRemaining()) {
               throw RuntimeException("junk remaining in buffer after lifting, something is very wrong!!")
           }
           return item
        } finally {
            RustBufferHelper.free(rbuf)
        }
    }
}

// FfiConverter that uses `RustBuffer` as the FfiType
public interface FfiConverterRustBuffer<KotlinType>: FfiConverter<KotlinType, RustBufferByValue> {
    override fun lift(value: RustBufferByValue): KotlinType = liftFromRustBuffer(value)
    override fun lower(value: KotlinType): RustBufferByValue = lowerIntoRustBuffer(value)
}

internal const val UNIFFI_CALL_SUCCESS = 0.toByte()
internal const val UNIFFI_CALL_ERROR = 1.toByte()
internal const val UNIFFI_CALL_UNEXPECTED_ERROR = 2.toByte()

// Default Implementations
internal fun UniffiRustCallStatus.isSuccess(): Boolean
    = code == UNIFFI_CALL_SUCCESS

internal fun UniffiRustCallStatus.isError(): Boolean
    = code == UNIFFI_CALL_ERROR

internal fun UniffiRustCallStatus.isPanic(): Boolean
    = code == UNIFFI_CALL_UNEXPECTED_ERROR

internal fun UniffiRustCallStatusByValue.isSuccess(): Boolean
    = code == UNIFFI_CALL_SUCCESS

internal fun UniffiRustCallStatusByValue.isError(): Boolean
    = code == UNIFFI_CALL_ERROR

internal fun UniffiRustCallStatusByValue.isPanic(): Boolean
    = code == UNIFFI_CALL_UNEXPECTED_ERROR

// Each top-level error class has a companion object that can lift the error from the call status's rust buffer
public interface UniffiRustCallStatusErrorHandler<E> {
    public fun lift(errorBuf: RustBufferByValue): E
}

// Helpers for calling Rust
// In practice we usually need to be synchronized to call this safely, so it doesn't
// synchronize itself

// Call a rust function that returns a Result<>.  Pass in the Error class companion that corresponds to the Err
internal inline fun <U, E: kotlin.Exception> uniffiRustCallWithError(errorHandler: UniffiRustCallStatusErrorHandler<E>, crossinline callback: (UniffiRustCallStatus) -> U): U {
    return UniffiRustCallStatusHelper.withReference() { status ->
        val returnValue = callback(status)
        uniffiCheckCallStatus(errorHandler, status)
        returnValue
    }
}

// Check `status` and throw an error if the call wasn't successful
internal fun<E: kotlin.Exception> uniffiCheckCallStatus(errorHandler: UniffiRustCallStatusErrorHandler<E>, status: UniffiRustCallStatus) {
    if (status.isSuccess()) {
        return
    } else if (status.isError()) {
        throw errorHandler.lift(status.errorBuf)
    } else if (status.isPanic()) {
        // when the rust code sees a panic, it tries to construct a rustbuffer
        // with the message.  but if that code panics, then it just sends back
        // an empty buffer.
        if (status.errorBuf.len > 0) {
            throw InternalException(FfiConverterString.lift(status.errorBuf))
        } else {
            throw InternalException("Rust panic")
        }
    } else {
        throw InternalException("Unknown rust call status: $status.code")
    }
}

// UniffiRustCallStatusErrorHandler implementation for times when we don't expect a CALL_ERROR
public object UniffiNullRustCallStatusErrorHandler: UniffiRustCallStatusErrorHandler<InternalException> {
    override fun lift(errorBuf: RustBufferByValue): InternalException {
        RustBufferHelper.free(errorBuf)
        return InternalException("Unexpected CALL_ERROR")
    }
}

// Call a rust function that returns a plain value
internal inline fun <U> uniffiRustCall(crossinline callback: (UniffiRustCallStatus) -> U): U {
    return uniffiRustCallWithError(UniffiNullRustCallStatusErrorHandler, callback)
}

internal inline fun<T> uniffiTraitInterfaceCall(
    callStatus: UniffiRustCallStatus,
    makeCall: () -> T,
    writeReturn: (T) -> Unit,
) {
    try {
        writeReturn(makeCall())
    } catch(e: kotlin.Exception) {
        callStatus.code = UNIFFI_CALL_UNEXPECTED_ERROR
        callStatus.errorBuf = FfiConverterString.lower(e.toString())
    }
}

internal inline fun<T, reified E: Throwable> uniffiTraitInterfaceCallWithError(
    callStatus: UniffiRustCallStatus,
    makeCall: () -> T,
    writeReturn: (T) -> Unit,
    lowerError: (E) -> RustBufferByValue
) {
    try {
        writeReturn(makeCall())
    } catch(e: kotlin.Exception) {
        if (e is E) {
            callStatus.code = UNIFFI_CALL_ERROR
            callStatus.errorBuf = lowerError(e)
        } else {
            callStatus.code = UNIFFI_CALL_UNEXPECTED_ERROR
            callStatus.errorBuf = FfiConverterString.lower(e.toString())
        }
    }
}

@Structure.FieldOrder("code", "errorBuf")
internal open class UniffiRustCallStatusStruct(
    @JvmField public var code: Byte,
    @JvmField public var errorBuf: RustBufferByValue,
) : Structure() {
    internal constructor(): this(0.toByte(), RustBufferByValue())

    internal class ByValue(
        code: Byte,
        errorBuf: RustBufferByValue,
    ): UniffiRustCallStatusStruct(code, errorBuf), Structure.ByValue {
        internal constructor(): this(0.toByte(), RustBufferByValue())
    }
    internal class ByReference(
        code: Byte,
        errorBuf: RustBufferByValue,
    ): UniffiRustCallStatusStruct(code, errorBuf), Structure.ByReference {
        internal constructor(): this(0.toByte(), RustBufferByValue())
    }
}

internal typealias UniffiRustCallStatus = UniffiRustCallStatusStruct.ByReference
internal typealias UniffiRustCallStatusByValue = UniffiRustCallStatusStruct.ByValue

internal object UniffiRustCallStatusHelper {
    internal fun allocValue() = UniffiRustCallStatusByValue()
    internal fun <U> withReference(block: (UniffiRustCallStatus) -> U): U {
        val status = UniffiRustCallStatus()
        return block(status)
    }
}

internal class UniffiHandleMap<T: Any> {
    private val map = java.util.concurrent.ConcurrentHashMap<Long, T>()
    private val counter: kotlinx.atomicfu.AtomicLong = kotlinx.atomicfu.atomic(1L)

    internal val size: Int
        get() = map.size

    // Insert a new object into the handle map and get a handle for it
    internal fun insert(obj: T): Long {
        val handle = counter.getAndAdd(1)
        map[handle] = obj
        return handle
    }

    // Get an object from the handle map
    internal fun get(handle: Long): T {
        return map[handle] ?: throw InternalException("UniffiHandleMap.get: Invalid handle")
    }

    // Remove an entry from the handlemap and get the Kotlin object back
    internal fun remove(handle: Long): T {
        return map.remove(handle) ?: throw InternalException("UniffiHandleMap.remove: Invalid handle")
    }
}

internal typealias ByteByReference = com.sun.jna.ptr.ByteByReference
internal typealias DoubleByReference = com.sun.jna.ptr.DoubleByReference
internal typealias FloatByReference = com.sun.jna.ptr.FloatByReference
internal typealias IntByReference = com.sun.jna.ptr.IntByReference
internal typealias LongByReference = com.sun.jna.ptr.LongByReference
internal typealias PointerByReference = com.sun.jna.ptr.PointerByReference
internal typealias ShortByReference = com.sun.jna.ptr.ShortByReference

// Contains loading, initialization code,
// and the FFI Function declarations in a com.sun.jna.Library.

// Define FFI callback types
internal interface UniffiRustFutureContinuationCallback: com.sun.jna.Callback {
    public fun callback(`data`: Long,`pollResult`: Byte,)
}
internal interface UniffiForeignFutureFree: com.sun.jna.Callback {
    public fun callback(`handle`: Long,)
}
internal interface UniffiCallbackInterfaceFree: com.sun.jna.Callback {
    public fun callback(`handle`: Long,)
}
@Structure.FieldOrder("handle", "free")
internal open class UniffiForeignFutureStruct(
    @JvmField public var `handle`: Long,
    @JvmField public var `free`: UniffiForeignFutureFree?,
) : com.sun.jna.Structure() {
    internal constructor(): this(
        
        `handle` = 0.toLong(),
        
        `free` = null,
        
    )

    internal class UniffiByValue(
        `handle`: Long,
        `free`: UniffiForeignFutureFree?,
    ): UniffiForeignFuture(`handle`,`free`,), Structure.ByValue
}

internal typealias UniffiForeignFuture = UniffiForeignFutureStruct

internal fun UniffiForeignFuture.uniffiSetValue(other: UniffiForeignFuture) {
    `handle` = other.`handle`
    `free` = other.`free`
}
internal fun UniffiForeignFuture.uniffiSetValue(other: UniffiForeignFutureUniffiByValue) {
    `handle` = other.`handle`
    `free` = other.`free`
}

internal typealias UniffiForeignFutureUniffiByValue = UniffiForeignFutureStruct.UniffiByValue
@Structure.FieldOrder("returnValue", "callStatus")
internal open class UniffiForeignFutureStructU8Struct(
    @JvmField public var `returnValue`: Byte,
    @JvmField public var `callStatus`: UniffiRustCallStatusByValue,
) : com.sun.jna.Structure() {
    internal constructor(): this(
        
        `returnValue` = 0.toByte(),
        
        `callStatus` = UniffiRustCallStatusHelper.allocValue(),
        
    )

    internal class UniffiByValue(
        `returnValue`: Byte,
        `callStatus`: UniffiRustCallStatusByValue,
    ): UniffiForeignFutureStructU8(`returnValue`,`callStatus`,), Structure.ByValue
}

internal typealias UniffiForeignFutureStructU8 = UniffiForeignFutureStructU8Struct

internal fun UniffiForeignFutureStructU8.uniffiSetValue(other: UniffiForeignFutureStructU8) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}
internal fun UniffiForeignFutureStructU8.uniffiSetValue(other: UniffiForeignFutureStructU8UniffiByValue) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}

internal typealias UniffiForeignFutureStructU8UniffiByValue = UniffiForeignFutureStructU8Struct.UniffiByValue
internal interface UniffiForeignFutureCompleteU8: com.sun.jna.Callback {
    public fun callback(`callbackData`: Long,`result`: UniffiForeignFutureStructU8UniffiByValue,)
}
@Structure.FieldOrder("returnValue", "callStatus")
internal open class UniffiForeignFutureStructI8Struct(
    @JvmField public var `returnValue`: Byte,
    @JvmField public var `callStatus`: UniffiRustCallStatusByValue,
) : com.sun.jna.Structure() {
    internal constructor(): this(
        
        `returnValue` = 0.toByte(),
        
        `callStatus` = UniffiRustCallStatusHelper.allocValue(),
        
    )

    internal class UniffiByValue(
        `returnValue`: Byte,
        `callStatus`: UniffiRustCallStatusByValue,
    ): UniffiForeignFutureStructI8(`returnValue`,`callStatus`,), Structure.ByValue
}

internal typealias UniffiForeignFutureStructI8 = UniffiForeignFutureStructI8Struct

internal fun UniffiForeignFutureStructI8.uniffiSetValue(other: UniffiForeignFutureStructI8) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}
internal fun UniffiForeignFutureStructI8.uniffiSetValue(other: UniffiForeignFutureStructI8UniffiByValue) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}

internal typealias UniffiForeignFutureStructI8UniffiByValue = UniffiForeignFutureStructI8Struct.UniffiByValue
internal interface UniffiForeignFutureCompleteI8: com.sun.jna.Callback {
    public fun callback(`callbackData`: Long,`result`: UniffiForeignFutureStructI8UniffiByValue,)
}
@Structure.FieldOrder("returnValue", "callStatus")
internal open class UniffiForeignFutureStructU16Struct(
    @JvmField public var `returnValue`: Short,
    @JvmField public var `callStatus`: UniffiRustCallStatusByValue,
) : com.sun.jna.Structure() {
    internal constructor(): this(
        
        `returnValue` = 0.toShort(),
        
        `callStatus` = UniffiRustCallStatusHelper.allocValue(),
        
    )

    internal class UniffiByValue(
        `returnValue`: Short,
        `callStatus`: UniffiRustCallStatusByValue,
    ): UniffiForeignFutureStructU16(`returnValue`,`callStatus`,), Structure.ByValue
}

internal typealias UniffiForeignFutureStructU16 = UniffiForeignFutureStructU16Struct

internal fun UniffiForeignFutureStructU16.uniffiSetValue(other: UniffiForeignFutureStructU16) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}
internal fun UniffiForeignFutureStructU16.uniffiSetValue(other: UniffiForeignFutureStructU16UniffiByValue) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}

internal typealias UniffiForeignFutureStructU16UniffiByValue = UniffiForeignFutureStructU16Struct.UniffiByValue
internal interface UniffiForeignFutureCompleteU16: com.sun.jna.Callback {
    public fun callback(`callbackData`: Long,`result`: UniffiForeignFutureStructU16UniffiByValue,)
}
@Structure.FieldOrder("returnValue", "callStatus")
internal open class UniffiForeignFutureStructI16Struct(
    @JvmField public var `returnValue`: Short,
    @JvmField public var `callStatus`: UniffiRustCallStatusByValue,
) : com.sun.jna.Structure() {
    internal constructor(): this(
        
        `returnValue` = 0.toShort(),
        
        `callStatus` = UniffiRustCallStatusHelper.allocValue(),
        
    )

    internal class UniffiByValue(
        `returnValue`: Short,
        `callStatus`: UniffiRustCallStatusByValue,
    ): UniffiForeignFutureStructI16(`returnValue`,`callStatus`,), Structure.ByValue
}

internal typealias UniffiForeignFutureStructI16 = UniffiForeignFutureStructI16Struct

internal fun UniffiForeignFutureStructI16.uniffiSetValue(other: UniffiForeignFutureStructI16) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}
internal fun UniffiForeignFutureStructI16.uniffiSetValue(other: UniffiForeignFutureStructI16UniffiByValue) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}

internal typealias UniffiForeignFutureStructI16UniffiByValue = UniffiForeignFutureStructI16Struct.UniffiByValue
internal interface UniffiForeignFutureCompleteI16: com.sun.jna.Callback {
    public fun callback(`callbackData`: Long,`result`: UniffiForeignFutureStructI16UniffiByValue,)
}
@Structure.FieldOrder("returnValue", "callStatus")
internal open class UniffiForeignFutureStructU32Struct(
    @JvmField public var `returnValue`: Int,
    @JvmField public var `callStatus`: UniffiRustCallStatusByValue,
) : com.sun.jna.Structure() {
    internal constructor(): this(
        
        `returnValue` = 0,
        
        `callStatus` = UniffiRustCallStatusHelper.allocValue(),
        
    )

    internal class UniffiByValue(
        `returnValue`: Int,
        `callStatus`: UniffiRustCallStatusByValue,
    ): UniffiForeignFutureStructU32(`returnValue`,`callStatus`,), Structure.ByValue
}

internal typealias UniffiForeignFutureStructU32 = UniffiForeignFutureStructU32Struct

internal fun UniffiForeignFutureStructU32.uniffiSetValue(other: UniffiForeignFutureStructU32) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}
internal fun UniffiForeignFutureStructU32.uniffiSetValue(other: UniffiForeignFutureStructU32UniffiByValue) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}

internal typealias UniffiForeignFutureStructU32UniffiByValue = UniffiForeignFutureStructU32Struct.UniffiByValue
internal interface UniffiForeignFutureCompleteU32: com.sun.jna.Callback {
    public fun callback(`callbackData`: Long,`result`: UniffiForeignFutureStructU32UniffiByValue,)
}
@Structure.FieldOrder("returnValue", "callStatus")
internal open class UniffiForeignFutureStructI32Struct(
    @JvmField public var `returnValue`: Int,
    @JvmField public var `callStatus`: UniffiRustCallStatusByValue,
) : com.sun.jna.Structure() {
    internal constructor(): this(
        
        `returnValue` = 0,
        
        `callStatus` = UniffiRustCallStatusHelper.allocValue(),
        
    )

    internal class UniffiByValue(
        `returnValue`: Int,
        `callStatus`: UniffiRustCallStatusByValue,
    ): UniffiForeignFutureStructI32(`returnValue`,`callStatus`,), Structure.ByValue
}

internal typealias UniffiForeignFutureStructI32 = UniffiForeignFutureStructI32Struct

internal fun UniffiForeignFutureStructI32.uniffiSetValue(other: UniffiForeignFutureStructI32) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}
internal fun UniffiForeignFutureStructI32.uniffiSetValue(other: UniffiForeignFutureStructI32UniffiByValue) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}

internal typealias UniffiForeignFutureStructI32UniffiByValue = UniffiForeignFutureStructI32Struct.UniffiByValue
internal interface UniffiForeignFutureCompleteI32: com.sun.jna.Callback {
    public fun callback(`callbackData`: Long,`result`: UniffiForeignFutureStructI32UniffiByValue,)
}
@Structure.FieldOrder("returnValue", "callStatus")
internal open class UniffiForeignFutureStructU64Struct(
    @JvmField public var `returnValue`: Long,
    @JvmField public var `callStatus`: UniffiRustCallStatusByValue,
) : com.sun.jna.Structure() {
    internal constructor(): this(
        
        `returnValue` = 0.toLong(),
        
        `callStatus` = UniffiRustCallStatusHelper.allocValue(),
        
    )

    internal class UniffiByValue(
        `returnValue`: Long,
        `callStatus`: UniffiRustCallStatusByValue,
    ): UniffiForeignFutureStructU64(`returnValue`,`callStatus`,), Structure.ByValue
}

internal typealias UniffiForeignFutureStructU64 = UniffiForeignFutureStructU64Struct

internal fun UniffiForeignFutureStructU64.uniffiSetValue(other: UniffiForeignFutureStructU64) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}
internal fun UniffiForeignFutureStructU64.uniffiSetValue(other: UniffiForeignFutureStructU64UniffiByValue) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}

internal typealias UniffiForeignFutureStructU64UniffiByValue = UniffiForeignFutureStructU64Struct.UniffiByValue
internal interface UniffiForeignFutureCompleteU64: com.sun.jna.Callback {
    public fun callback(`callbackData`: Long,`result`: UniffiForeignFutureStructU64UniffiByValue,)
}
@Structure.FieldOrder("returnValue", "callStatus")
internal open class UniffiForeignFutureStructI64Struct(
    @JvmField public var `returnValue`: Long,
    @JvmField public var `callStatus`: UniffiRustCallStatusByValue,
) : com.sun.jna.Structure() {
    internal constructor(): this(
        
        `returnValue` = 0.toLong(),
        
        `callStatus` = UniffiRustCallStatusHelper.allocValue(),
        
    )

    internal class UniffiByValue(
        `returnValue`: Long,
        `callStatus`: UniffiRustCallStatusByValue,
    ): UniffiForeignFutureStructI64(`returnValue`,`callStatus`,), Structure.ByValue
}

internal typealias UniffiForeignFutureStructI64 = UniffiForeignFutureStructI64Struct

internal fun UniffiForeignFutureStructI64.uniffiSetValue(other: UniffiForeignFutureStructI64) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}
internal fun UniffiForeignFutureStructI64.uniffiSetValue(other: UniffiForeignFutureStructI64UniffiByValue) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}

internal typealias UniffiForeignFutureStructI64UniffiByValue = UniffiForeignFutureStructI64Struct.UniffiByValue
internal interface UniffiForeignFutureCompleteI64: com.sun.jna.Callback {
    public fun callback(`callbackData`: Long,`result`: UniffiForeignFutureStructI64UniffiByValue,)
}
@Structure.FieldOrder("returnValue", "callStatus")
internal open class UniffiForeignFutureStructF32Struct(
    @JvmField public var `returnValue`: Float,
    @JvmField public var `callStatus`: UniffiRustCallStatusByValue,
) : com.sun.jna.Structure() {
    internal constructor(): this(
        
        `returnValue` = 0.0f,
        
        `callStatus` = UniffiRustCallStatusHelper.allocValue(),
        
    )

    internal class UniffiByValue(
        `returnValue`: Float,
        `callStatus`: UniffiRustCallStatusByValue,
    ): UniffiForeignFutureStructF32(`returnValue`,`callStatus`,), Structure.ByValue
}

internal typealias UniffiForeignFutureStructF32 = UniffiForeignFutureStructF32Struct

internal fun UniffiForeignFutureStructF32.uniffiSetValue(other: UniffiForeignFutureStructF32) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}
internal fun UniffiForeignFutureStructF32.uniffiSetValue(other: UniffiForeignFutureStructF32UniffiByValue) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}

internal typealias UniffiForeignFutureStructF32UniffiByValue = UniffiForeignFutureStructF32Struct.UniffiByValue
internal interface UniffiForeignFutureCompleteF32: com.sun.jna.Callback {
    public fun callback(`callbackData`: Long,`result`: UniffiForeignFutureStructF32UniffiByValue,)
}
@Structure.FieldOrder("returnValue", "callStatus")
internal open class UniffiForeignFutureStructF64Struct(
    @JvmField public var `returnValue`: Double,
    @JvmField public var `callStatus`: UniffiRustCallStatusByValue,
) : com.sun.jna.Structure() {
    internal constructor(): this(
        
        `returnValue` = 0.0,
        
        `callStatus` = UniffiRustCallStatusHelper.allocValue(),
        
    )

    internal class UniffiByValue(
        `returnValue`: Double,
        `callStatus`: UniffiRustCallStatusByValue,
    ): UniffiForeignFutureStructF64(`returnValue`,`callStatus`,), Structure.ByValue
}

internal typealias UniffiForeignFutureStructF64 = UniffiForeignFutureStructF64Struct

internal fun UniffiForeignFutureStructF64.uniffiSetValue(other: UniffiForeignFutureStructF64) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}
internal fun UniffiForeignFutureStructF64.uniffiSetValue(other: UniffiForeignFutureStructF64UniffiByValue) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}

internal typealias UniffiForeignFutureStructF64UniffiByValue = UniffiForeignFutureStructF64Struct.UniffiByValue
internal interface UniffiForeignFutureCompleteF64: com.sun.jna.Callback {
    public fun callback(`callbackData`: Long,`result`: UniffiForeignFutureStructF64UniffiByValue,)
}
@Structure.FieldOrder("returnValue", "callStatus")
internal open class UniffiForeignFutureStructPointerStruct(
    @JvmField public var `returnValue`: Pointer?,
    @JvmField public var `callStatus`: UniffiRustCallStatusByValue,
) : com.sun.jna.Structure() {
    internal constructor(): this(
        
        `returnValue` = NullPointer,
        
        `callStatus` = UniffiRustCallStatusHelper.allocValue(),
        
    )

    internal class UniffiByValue(
        `returnValue`: Pointer?,
        `callStatus`: UniffiRustCallStatusByValue,
    ): UniffiForeignFutureStructPointer(`returnValue`,`callStatus`,), Structure.ByValue
}

internal typealias UniffiForeignFutureStructPointer = UniffiForeignFutureStructPointerStruct

internal fun UniffiForeignFutureStructPointer.uniffiSetValue(other: UniffiForeignFutureStructPointer) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}
internal fun UniffiForeignFutureStructPointer.uniffiSetValue(other: UniffiForeignFutureStructPointerUniffiByValue) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}

internal typealias UniffiForeignFutureStructPointerUniffiByValue = UniffiForeignFutureStructPointerStruct.UniffiByValue
internal interface UniffiForeignFutureCompletePointer: com.sun.jna.Callback {
    public fun callback(`callbackData`: Long,`result`: UniffiForeignFutureStructPointerUniffiByValue,)
}
@Structure.FieldOrder("returnValue", "callStatus")
internal open class UniffiForeignFutureStructRustBufferStruct(
    @JvmField public var `returnValue`: RustBufferByValue,
    @JvmField public var `callStatus`: UniffiRustCallStatusByValue,
) : com.sun.jna.Structure() {
    internal constructor(): this(
        
        `returnValue` = RustBufferHelper.allocValue(),
        
        `callStatus` = UniffiRustCallStatusHelper.allocValue(),
        
    )

    internal class UniffiByValue(
        `returnValue`: RustBufferByValue,
        `callStatus`: UniffiRustCallStatusByValue,
    ): UniffiForeignFutureStructRustBuffer(`returnValue`,`callStatus`,), Structure.ByValue
}

internal typealias UniffiForeignFutureStructRustBuffer = UniffiForeignFutureStructRustBufferStruct

internal fun UniffiForeignFutureStructRustBuffer.uniffiSetValue(other: UniffiForeignFutureStructRustBuffer) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}
internal fun UniffiForeignFutureStructRustBuffer.uniffiSetValue(other: UniffiForeignFutureStructRustBufferUniffiByValue) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}

internal typealias UniffiForeignFutureStructRustBufferUniffiByValue = UniffiForeignFutureStructRustBufferStruct.UniffiByValue
internal interface UniffiForeignFutureCompleteRustBuffer: com.sun.jna.Callback {
    public fun callback(`callbackData`: Long,`result`: UniffiForeignFutureStructRustBufferUniffiByValue,)
}
@Structure.FieldOrder("callStatus")
internal open class UniffiForeignFutureStructVoidStruct(
    @JvmField public var `callStatus`: UniffiRustCallStatusByValue,
) : com.sun.jna.Structure() {
    internal constructor(): this(
        
        `callStatus` = UniffiRustCallStatusHelper.allocValue(),
        
    )

    internal class UniffiByValue(
        `callStatus`: UniffiRustCallStatusByValue,
    ): UniffiForeignFutureStructVoid(`callStatus`,), Structure.ByValue
}

internal typealias UniffiForeignFutureStructVoid = UniffiForeignFutureStructVoidStruct

internal fun UniffiForeignFutureStructVoid.uniffiSetValue(other: UniffiForeignFutureStructVoid) {
    `callStatus` = other.`callStatus`
}
internal fun UniffiForeignFutureStructVoid.uniffiSetValue(other: UniffiForeignFutureStructVoidUniffiByValue) {
    `callStatus` = other.`callStatus`
}

internal typealias UniffiForeignFutureStructVoidUniffiByValue = UniffiForeignFutureStructVoidStruct.UniffiByValue
internal interface UniffiForeignFutureCompleteVoid: com.sun.jna.Callback {
    public fun callback(`callbackData`: Long,`result`: UniffiForeignFutureStructVoidUniffiByValue,)
}
internal interface UniffiCallbackInterfaceOnPeerDiscoveredMethod0: com.sun.jna.Callback {
    public fun callback(`uniffiHandle`: Long,`peer`: RustBufferByValue,`uniffiOutReturn`: Pointer,uniffiCallStatus: UniffiRustCallStatus,)
}
internal interface UniffiCallbackInterfaceOnPeerDiscoveredMethod1: com.sun.jna.Callback {
    public fun callback(`uniffiHandle`: Long,`peer`: RustBufferByValue,`uniffiOutReturn`: Pointer,uniffiCallStatus: UniffiRustCallStatus,)
}
internal interface UniffiCallbackInterfaceOnPeerDiscoveredMethod2: com.sun.jna.Callback {
    public fun callback(`uniffiHandle`: Long,`nodeId`: RustBufferByValue,`uniffiOutReturn`: Pointer,uniffiCallStatus: UniffiRustCallStatus,)
}
internal interface UniffiCallbackInterfaceOnPeerDiscoveredMethod3: com.sun.jna.Callback {
    public fun callback(`uniffiHandle`: Long,`code`: RustBufferByValue,`message`: RustBufferByValue,`uniffiOutReturn`: Pointer,uniffiCallStatus: UniffiRustCallStatus,)
}
internal interface UniffiCallbackInterfaceSecureSessionListenerMethod0: com.sun.jna.Callback {
    public fun callback(`uniffiHandle`: Long,`state`: RustBufferByValue,`detail`: RustBufferByValue,`uniffiOutReturn`: Pointer,uniffiCallStatus: UniffiRustCallStatus,)
}
internal interface UniffiCallbackInterfaceSecureSessionListenerMethod1: com.sun.jna.Callback {
    public fun callback(`uniffiHandle`: Long,`message`: RustBufferByValue,`uniffiOutReturn`: Pointer,uniffiCallStatus: UniffiRustCallStatus,)
}
@Structure.FieldOrder("onPeerDiscovered", "onPeerUpdated", "onPeerLost", "onError", "uniffiFree")
internal open class UniffiVTableCallbackInterfaceOnPeerDiscoveredStruct(
    @JvmField public var `onPeerDiscovered`: UniffiCallbackInterfaceOnPeerDiscoveredMethod0?,
    @JvmField public var `onPeerUpdated`: UniffiCallbackInterfaceOnPeerDiscoveredMethod1?,
    @JvmField public var `onPeerLost`: UniffiCallbackInterfaceOnPeerDiscoveredMethod2?,
    @JvmField public var `onError`: UniffiCallbackInterfaceOnPeerDiscoveredMethod3?,
    @JvmField public var `uniffiFree`: UniffiCallbackInterfaceFree?,
) : com.sun.jna.Structure() {
    internal constructor(): this(
        
        `onPeerDiscovered` = null,
        
        `onPeerUpdated` = null,
        
        `onPeerLost` = null,
        
        `onError` = null,
        
        `uniffiFree` = null,
        
    )

    internal class UniffiByValue(
        `onPeerDiscovered`: UniffiCallbackInterfaceOnPeerDiscoveredMethod0?,
        `onPeerUpdated`: UniffiCallbackInterfaceOnPeerDiscoveredMethod1?,
        `onPeerLost`: UniffiCallbackInterfaceOnPeerDiscoveredMethod2?,
        `onError`: UniffiCallbackInterfaceOnPeerDiscoveredMethod3?,
        `uniffiFree`: UniffiCallbackInterfaceFree?,
    ): UniffiVTableCallbackInterfaceOnPeerDiscovered(`onPeerDiscovered`,`onPeerUpdated`,`onPeerLost`,`onError`,`uniffiFree`,), Structure.ByValue
}

internal typealias UniffiVTableCallbackInterfaceOnPeerDiscovered = UniffiVTableCallbackInterfaceOnPeerDiscoveredStruct

internal fun UniffiVTableCallbackInterfaceOnPeerDiscovered.uniffiSetValue(other: UniffiVTableCallbackInterfaceOnPeerDiscovered) {
    `onPeerDiscovered` = other.`onPeerDiscovered`
    `onPeerUpdated` = other.`onPeerUpdated`
    `onPeerLost` = other.`onPeerLost`
    `onError` = other.`onError`
    `uniffiFree` = other.`uniffiFree`
}
internal fun UniffiVTableCallbackInterfaceOnPeerDiscovered.uniffiSetValue(other: UniffiVTableCallbackInterfaceOnPeerDiscoveredUniffiByValue) {
    `onPeerDiscovered` = other.`onPeerDiscovered`
    `onPeerUpdated` = other.`onPeerUpdated`
    `onPeerLost` = other.`onPeerLost`
    `onError` = other.`onError`
    `uniffiFree` = other.`uniffiFree`
}

internal typealias UniffiVTableCallbackInterfaceOnPeerDiscoveredUniffiByValue = UniffiVTableCallbackInterfaceOnPeerDiscoveredStruct.UniffiByValue
@Structure.FieldOrder("onState", "onMessage", "uniffiFree")
internal open class UniffiVTableCallbackInterfaceSecureSessionListenerStruct(
    @JvmField public var `onState`: UniffiCallbackInterfaceSecureSessionListenerMethod0?,
    @JvmField public var `onMessage`: UniffiCallbackInterfaceSecureSessionListenerMethod1?,
    @JvmField public var `uniffiFree`: UniffiCallbackInterfaceFree?,
) : com.sun.jna.Structure() {
    internal constructor(): this(
        
        `onState` = null,
        
        `onMessage` = null,
        
        `uniffiFree` = null,
        
    )

    internal class UniffiByValue(
        `onState`: UniffiCallbackInterfaceSecureSessionListenerMethod0?,
        `onMessage`: UniffiCallbackInterfaceSecureSessionListenerMethod1?,
        `uniffiFree`: UniffiCallbackInterfaceFree?,
    ): UniffiVTableCallbackInterfaceSecureSessionListener(`onState`,`onMessage`,`uniffiFree`,), Structure.ByValue
}

internal typealias UniffiVTableCallbackInterfaceSecureSessionListener = UniffiVTableCallbackInterfaceSecureSessionListenerStruct

internal fun UniffiVTableCallbackInterfaceSecureSessionListener.uniffiSetValue(other: UniffiVTableCallbackInterfaceSecureSessionListener) {
    `onState` = other.`onState`
    `onMessage` = other.`onMessage`
    `uniffiFree` = other.`uniffiFree`
}
internal fun UniffiVTableCallbackInterfaceSecureSessionListener.uniffiSetValue(other: UniffiVTableCallbackInterfaceSecureSessionListenerUniffiByValue) {
    `onState` = other.`onState`
    `onMessage` = other.`onMessage`
    `uniffiFree` = other.`uniffiFree`
}

internal typealias UniffiVTableCallbackInterfaceSecureSessionListenerUniffiByValue = UniffiVTableCallbackInterfaceSecureSessionListenerStruct.UniffiByValue
































































































































































@Synchronized
private fun findLibraryName(componentName: String): String {
    val libOverride = System.getProperty("uniffi.component.$componentName.libraryOverride")
    if (libOverride != null) {
        return libOverride
    }
    return "luciola_uniffi"
}

// For large crates we prevent `MethodTooLargeException` (see #2340)
// N.B. the name of the extension is very misleading, since it is 
// rather `InterfaceTooLargeException`, caused by too many methods 
// in the interface for large crates.
//
// By splitting the otherwise huge interface into two parts
// * UniffiLib 
// * IntegrityCheckingUniffiLib (this)
// we allow for ~2x as many methods in the UniffiLib interface.
// 
// The `ffi_uniffi_contract_version` method and all checksum methods are put 
// into `IntegrityCheckingUniffiLib` and these methods are called only once,
// when the library is loaded.
internal object IntegrityCheckingUniffiLib : Library {
    init {
        Native.register(IntegrityCheckingUniffiLib::class.java, findLibraryName("luciola_uniffi"))
        uniffiCheckContractApiVersion()
        uniffiCheckApiChecksums()
    }

    private fun uniffiCheckContractApiVersion() {
        // Get the bindings contract version from our ComponentInterface
        val bindingsContractVersion = 29
        // Get the scaffolding contract version by calling the into the dylib
        val scaffoldingContractVersion = ffi_luciola_uniffi_uniffi_contract_version()
        if (bindingsContractVersion != scaffoldingContractVersion) {
            throw RuntimeException("UniFFI contract version mismatch: try cleaning and rebuilding your project")
        }
    }
    private fun uniffiCheckApiChecksums() {
        if (uniffi_luciola_uniffi_checksum_func_advertised_addresses() != 49550.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_build_pairing_uri() != 28829.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_comparison_pin() != 2657.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_default_race_candidates() != 52364.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_generate_device_identity() != 39160.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_get_device_meta() != 13951.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_identity_fingerprint() != 8719.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_identity_from_seed() != 31545.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_identity_short_pin() != 19700.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_is_lan_peer() != 63646.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_is_physical_nic() != 55757.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_is_tun_virtual_ip() != 53707.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_is_virtual_nic() != 39009.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_local_candidate_addresses() != 47155.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_parse_pairing_uri() != 57854.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_race_connect() != 26451.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_render_qr_ascii() != 34654.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_select_lan_ip() != 61023.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_sign_message() != 47227.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_subnet_broadcast_addresses() != 6105.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_verify_message() != 57140.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_discoverysession_is_bound() != 50984.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_discoverysession_node_id() != 23559.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_discoverysession_restart() != 7511.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_discoverysession_seconds_since_idle() != 7024.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_discoverysession_set_manual_peers() != 43607.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_discoverysession_start() != 53880.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_discoverysession_stop() != 1480.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securesession_connect() != 20557.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securesession_disconnect() != 52412.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securesession_is_connected() != 58467.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securesession_listen() != 14622.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securesession_send() != 21703.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securesession_set_keepalive() != 2432.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securesession_set_retry_policy() != 49064.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securesession_stats() != 9425.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_truststore_entries() != 19413.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_truststore_level_of() != 49100.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_truststore_remove() != 61647.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_truststore_to_json() != 25922.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_truststore_trust_device() != 27542.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_constructor_discoverysession_new() != 12135.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_constructor_securesession_new() != 24675.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_constructor_truststore_new() != 2274.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_onpeerdiscovered_on_peer_discovered() != 31116.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_onpeerdiscovered_on_peer_updated() != 47301.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_onpeerdiscovered_on_peer_lost() != 28239.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_onpeerdiscovered_on_error() != 29273.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securesessionlistener_on_state() != 43161.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securesessionlistener_on_message() != 6008.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
    }

    // Integrity check functions only
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_advertised_addresses(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_build_pairing_uri(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_comparison_pin(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_default_race_candidates(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_generate_device_identity(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_get_device_meta(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_identity_fingerprint(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_identity_from_seed(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_identity_short_pin(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_is_lan_peer(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_is_physical_nic(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_is_tun_virtual_ip(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_is_virtual_nic(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_local_candidate_addresses(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_parse_pairing_uri(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_race_connect(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_render_qr_ascii(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_select_lan_ip(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_sign_message(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_subnet_broadcast_addresses(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_verify_message(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_discoverysession_is_bound(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_discoverysession_node_id(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_discoverysession_restart(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_discoverysession_seconds_since_idle(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_discoverysession_set_manual_peers(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_discoverysession_start(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_discoverysession_stop(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securesession_connect(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securesession_disconnect(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securesession_is_connected(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securesession_listen(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securesession_send(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securesession_set_keepalive(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securesession_set_retry_policy(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securesession_stats(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_truststore_entries(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_truststore_level_of(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_truststore_remove(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_truststore_to_json(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_truststore_trust_device(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_constructor_discoverysession_new(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_constructor_securesession_new(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_constructor_truststore_new(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_onpeerdiscovered_on_peer_discovered(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_onpeerdiscovered_on_peer_updated(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_onpeerdiscovered_on_peer_lost(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_onpeerdiscovered_on_error(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securesessionlistener_on_state(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securesessionlistener_on_message(
    ): Short
    @JvmStatic
    external fun ffi_luciola_uniffi_uniffi_contract_version(
    ): Int
}

// A JNA Library to expose the extern-C FFI definitions.
// This is an implementation detail which will be called internally by the public API.
internal object UniffiLib : Library {

    init {
        IntegrityCheckingUniffiLib
        Native.register(UniffiLib::class.java, findLibraryName("luciola_uniffi"))
        // No need to check the contract version and checksums, since 
        // we already did that with `IntegrityCheckingUniffiLib` above.
        uniffiCallbackInterfaceOnPeerDiscovered.register(this)
        uniffiCallbackInterfaceSecureSessionListener.register(this)
    }
    // The Cleaner for the whole library
    internal val CLEANER: UniffiCleaner by lazy {
        UniffiCleaner.create()
    }
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_clone_discoverysession(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Pointer?
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_free_discoverysession(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_constructor_discoverysession_new(
        `name`: RustBufferByValue,
        `port`: Short,
        `manualPeers`: RustBufferByValue,
        `product`: RustBufferByValue,
        `extra`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Pointer?
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_discoverysession_is_bound(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_discoverysession_node_id(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_discoverysession_restart(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_discoverysession_seconds_since_idle(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Double
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_discoverysession_set_manual_peers(
        `ptr`: Pointer?,
        `peers`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_discoverysession_start(
        `ptr`: Pointer?,
        `listener`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_discoverysession_stop(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_clone_securesession(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Pointer?
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_free_securesession(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_constructor_securesession_new(
        `identitySeed`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Pointer?
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_securesession_connect(
        `ptr`: Pointer?,
        `addresses`: RustBufferByValue,
        `port`: Short,
        `pinnedPeerPublicKey`: RustBufferByValue,
        `autoReconnect`: Byte,
        `listener`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_securesession_disconnect(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_securesession_is_connected(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_securesession_listen(
        `ptr`: Pointer?,
        `port`: Short,
        `expectedPeer`: RustBufferByValue,
        `listener`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_securesession_send(
        `ptr`: Pointer?,
        `message`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_securesession_set_keepalive(
        `ptr`: Pointer?,
        `intervalMs`: Long,
        `deadAfterMs`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_securesession_set_retry_policy(
        `ptr`: Pointer?,
        `minMs`: Long,
        `maxMs`: Long,
        `jitterPct`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_securesession_stats(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_clone_truststore(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Pointer?
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_free_truststore(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_constructor_truststore_new(
        `fromJson`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Pointer?
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_truststore_entries(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_truststore_level_of(
        `ptr`: Pointer?,
        `publicKey`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_truststore_remove(
        `ptr`: Pointer?,
        `fingerprint`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_truststore_to_json(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_truststore_trust_device(
        `ptr`: Pointer?,
        `device`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_init_callback_vtable_onpeerdiscovered(
        `vtable`: UniffiVTableCallbackInterfaceOnPeerDiscovered,
    ): Unit
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_init_callback_vtable_securesessionlistener(
        `vtable`: UniffiVTableCallbackInterfaceSecureSessionListener,
    ): Unit
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_advertised_addresses(
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_build_pairing_uri(
        `name`: RustBufferByValue,
        `product`: RustBufferByValue,
        `port`: Short,
        `addrs`: RustBufferByValue,
        `fingerprint`: RustBufferByValue,
        `publicKey`: RustBufferByValue,
        `pin`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_comparison_pin(
        `localPk`: RustBufferByValue,
        `remotePk`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_default_race_candidates(
        `addresses`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_generate_device_identity(
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_get_device_meta(
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_identity_fingerprint(
        `publicKey`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_identity_from_seed(
        `seed`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_identity_short_pin(
        `publicKey`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_is_lan_peer(
        `peerAddress`: RustBufferByValue,
        `localAddresses`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_is_physical_nic(
        `name`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_is_tun_virtual_ip(
        `address`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_is_virtual_nic(
        `name`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_local_candidate_addresses(
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_parse_pairing_uri(
        `uri`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_race_connect(
        `addresses`: RustBufferByValue,
        `port`: Short,
        `attemptTimeoutMs`: RustBufferByValue,
        `staggerMs`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_render_qr_ascii(
        `content`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_select_lan_ip(
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_sign_message(
        `seed`: RustBufferByValue,
        `message`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_subnet_broadcast_addresses(
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_verify_message(
        `publicKey`: RustBufferByValue,
        `message`: RustBufferByValue,
        `signature`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte
    @JvmStatic
    external fun ffi_luciola_uniffi_rustbuffer_alloc(
        `size`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun ffi_luciola_uniffi_rustbuffer_from_bytes(
        `bytes`: ForeignBytesByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun ffi_luciola_uniffi_rustbuffer_free(
        `buf`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rustbuffer_reserve(
        `buf`: RustBufferByValue,
        `additional`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_poll_u8(
        `handle`: Long,
        `callback`: UniffiRustFutureContinuationCallback,
        `callbackData`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_cancel_u8(
        `handle`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_free_u8(
        `handle`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_complete_u8(
        `handle`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_poll_i8(
        `handle`: Long,
        `callback`: UniffiRustFutureContinuationCallback,
        `callbackData`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_cancel_i8(
        `handle`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_free_i8(
        `handle`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_complete_i8(
        `handle`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_poll_u16(
        `handle`: Long,
        `callback`: UniffiRustFutureContinuationCallback,
        `callbackData`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_cancel_u16(
        `handle`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_free_u16(
        `handle`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_complete_u16(
        `handle`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Short
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_poll_i16(
        `handle`: Long,
        `callback`: UniffiRustFutureContinuationCallback,
        `callbackData`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_cancel_i16(
        `handle`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_free_i16(
        `handle`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_complete_i16(
        `handle`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Short
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_poll_u32(
        `handle`: Long,
        `callback`: UniffiRustFutureContinuationCallback,
        `callbackData`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_cancel_u32(
        `handle`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_free_u32(
        `handle`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_complete_u32(
        `handle`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Int
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_poll_i32(
        `handle`: Long,
        `callback`: UniffiRustFutureContinuationCallback,
        `callbackData`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_cancel_i32(
        `handle`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_free_i32(
        `handle`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_complete_i32(
        `handle`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Int
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_poll_u64(
        `handle`: Long,
        `callback`: UniffiRustFutureContinuationCallback,
        `callbackData`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_cancel_u64(
        `handle`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_free_u64(
        `handle`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_complete_u64(
        `handle`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Long
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_poll_i64(
        `handle`: Long,
        `callback`: UniffiRustFutureContinuationCallback,
        `callbackData`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_cancel_i64(
        `handle`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_free_i64(
        `handle`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_complete_i64(
        `handle`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Long
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_poll_f32(
        `handle`: Long,
        `callback`: UniffiRustFutureContinuationCallback,
        `callbackData`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_cancel_f32(
        `handle`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_free_f32(
        `handle`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_complete_f32(
        `handle`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Float
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_poll_f64(
        `handle`: Long,
        `callback`: UniffiRustFutureContinuationCallback,
        `callbackData`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_cancel_f64(
        `handle`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_free_f64(
        `handle`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_complete_f64(
        `handle`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Double
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_poll_pointer(
        `handle`: Long,
        `callback`: UniffiRustFutureContinuationCallback,
        `callbackData`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_cancel_pointer(
        `handle`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_free_pointer(
        `handle`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_complete_pointer(
        `handle`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Pointer?
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_poll_rust_buffer(
        `handle`: Long,
        `callback`: UniffiRustFutureContinuationCallback,
        `callbackData`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_cancel_rust_buffer(
        `handle`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_free_rust_buffer(
        `handle`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_complete_rust_buffer(
        `handle`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_poll_void(
        `handle`: Long,
        `callback`: UniffiRustFutureContinuationCallback,
        `callbackData`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_cancel_void(
        `handle`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_free_void(
        `handle`: Long,
    ): Unit
    @JvmStatic
    external fun ffi_luciola_uniffi_rust_future_complete_void(
        `handle`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit
}

public fun uniffiEnsureInitialized() {
    UniffiLib
}

// Public interface members begin here.

internal const val IDX_CALLBACK_FREE = 0
// Callback return codes
internal const val UNIFFI_CALLBACK_SUCCESS = 0
internal const val UNIFFI_CALLBACK_ERROR = 1
internal const val UNIFFI_CALLBACK_UNEXPECTED_ERROR = 2

public abstract class FfiConverterCallbackInterface<CallbackInterface: Any>: FfiConverter<CallbackInterface, Long> {
    internal val handleMap = UniffiHandleMap<CallbackInterface>()

    internal fun drop(handle: Long) {
        handleMap.remove(handle)
    }

    override fun lift(value: Long): CallbackInterface {
        return handleMap.get(value)
    }

    override fun read(buf: ByteBuffer): CallbackInterface = lift(buf.getLong())

    override fun lower(value: CallbackInterface): Long = handleMap.insert(value)

    override fun allocationSize(value: CallbackInterface): ULong = 8UL

    override fun write(value: CallbackInterface, buf: ByteBuffer) {
        buf.putLong(lower(value))
    }
}
// The cleaner interface for Object finalization code to run.
// This is the entry point to any implementation that we're using.
//
// The cleaner registers disposables and returns cleanables, so now we are
// defining a `UniffiCleaner` with a `UniffiClenaer.Cleanable` to abstract the
// different implementations available at compile time.
public interface UniffiCleaner {
    public interface Cleanable {
        public fun clean()
    }

    public fun register(resource: Any, disposable: Disposable): UniffiCleaner.Cleanable

    public companion object
}
// The fallback Jna cleaner, which is available for both Android, and the JVM.
private class UniffiJnaCleaner : UniffiCleaner {
    private val cleaner = com.sun.jna.internal.Cleaner.getCleaner()

    override fun register(resource: Any, disposable: Disposable): UniffiCleaner.Cleanable =
        UniffiJnaCleanable(cleaner.register(resource, UniffiCleanerAction(disposable)))
}

private class UniffiJnaCleanable(
    private val cleanable: com.sun.jna.internal.Cleaner.Cleanable,
) : UniffiCleaner.Cleanable {
    override fun clean() = cleanable.clean()
}

private class UniffiCleanerAction(private val disposable: Disposable): Runnable {
    override fun run() {
        disposable.destroy()
    }
}

// The SystemCleaner, available from API Level 33.
// Some API Level 33 OSes do not support using it, so we require API Level 34.
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
private class AndroidSystemCleaner : UniffiCleaner {
    private val cleaner = android.system.SystemCleaner.cleaner()

    override fun register(resource: Any, disposable: Disposable): UniffiCleaner.Cleanable =
        AndroidSystemCleanable(cleaner.register(resource, UniffiCleanerAction(disposable)))
}

@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
private class AndroidSystemCleanable(
    private val cleanable: java.lang.ref.Cleaner.Cleanable,
) : UniffiCleaner.Cleanable {
    override fun clean() = cleanable.clean()
}

private fun UniffiCleaner.Companion.create(): UniffiCleaner {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
        try {
            return AndroidSystemCleaner()
        } catch (_: IllegalAccessError) {
            // (For Compose preview) Fallback to UniffiJnaCleaner if AndroidSystemCleaner is
            // unavailable, even for API level 34 or higher.
        }
    }
    return UniffiJnaCleaner()
}


public object FfiConverterUShort: FfiConverter<UShort, Short> {
    override fun lift(value: Short): UShort {
        return value.toUShort()
    }

    override fun read(buf: ByteBuffer): UShort {
        return lift(buf.getShort())
    }

    override fun lower(value: UShort): Short {
        return value.toShort()
    }

    override fun allocationSize(value: UShort): ULong = 2UL

    override fun write(value: UShort, buf: ByteBuffer) {
        buf.putShort(value.toShort())
    }
}


public object FfiConverterULong: FfiConverter<ULong, Long> {
    override fun lift(value: Long): ULong {
        return value.toULong()
    }

    override fun read(buf: ByteBuffer): ULong {
        return lift(buf.getLong())
    }

    override fun lower(value: ULong): Long {
        return value.toLong()
    }

    override fun allocationSize(value: ULong): ULong = 8UL

    override fun write(value: ULong, buf: ByteBuffer) {
        buf.putLong(value.toLong())
    }
}


public object FfiConverterDouble: FfiConverter<Double, Double> {
    override fun lift(value: Double): Double {
        return value
    }

    override fun read(buf: ByteBuffer): Double {
        return buf.getDouble()
    }

    override fun lower(value: Double): Double {
        return value
    }

    override fun allocationSize(value: Double): ULong = 8UL

    override fun write(value: Double, buf: ByteBuffer) {
        buf.putDouble(value)
    }
}


public object FfiConverterBoolean: FfiConverter<Boolean, Byte> {
    override fun lift(value: Byte): Boolean {
        return value.toInt() != 0
    }

    override fun read(buf: ByteBuffer): Boolean {
        return lift(buf.get())
    }

    override fun lower(value: Boolean): Byte {
        return if (value) 1.toByte() else 0.toByte()
    }

    override fun allocationSize(value: Boolean): ULong = 1UL

    override fun write(value: Boolean, buf: ByteBuffer) {
        buf.put(lower(value))
    }
}


public object FfiConverterString: FfiConverter<String, RustBufferByValue> {
    // Note: we don't inherit from FfiConverterRustBuffer, because we use a
    // special encoding when lowering/lifting.  We can use `RustBuffer.len` to
    // store our length and avoid writing it out to the buffer.
    override fun lift(value: RustBufferByValue): String {
        try {
            require(value.len <= Int.MAX_VALUE) {
        val length = value.len
        "cannot handle RustBuffer longer than Int.MAX_VALUE bytes: length is $length"
    }
            val byteArr =  value.asByteBuffer()!!.get(value.len.toInt())
            return byteArr.decodeToString()
        } finally {
            RustBufferHelper.free(value)
        }
    }

    override fun read(buf: ByteBuffer): String {
        val len = buf.getInt()
        val byteArr = buf.get(len)
        return byteArr.decodeToString()
    }

    override fun lower(value: String): RustBufferByValue {
        // TODO: prevent allocating a new byte array here
        val encoded = value.encodeToByteArray(throwOnInvalidSequence = true)
        return RustBufferHelper.allocValue(encoded.size.toULong()).apply {
            asByteBuffer()!!.put(encoded)
        }
    }

    // We aren't sure exactly how many bytes our string will be once it's UTF-8
    // encoded.  Allocate 3 bytes per UTF-16 code unit which will always be
    // enough.
    override fun allocationSize(value: String): ULong {
        val sizeForLength = 4UL
        val sizeForString = value.length.toULong() * 3UL
        return sizeForLength + sizeForString
    }

    override fun write(value: String, buf: ByteBuffer) {
        // TODO: prevent allocating a new byte array here
        val encoded = value.encodeToByteArray(throwOnInvalidSequence = true)
        buf.putInt(encoded.size)
        buf.put(encoded)
    }
}


public object FfiConverterByteArray: FfiConverterRustBuffer<ByteArray> {
    override fun read(buf: ByteBuffer): ByteArray {
        val len = buf.getInt()
        val byteArr = buf.get(len)
        return byteArr
    }
    override fun allocationSize(value: ByteArray): ULong {
        return 4UL + value.size.toULong()
    }
    override fun write(value: ByteArray, buf: ByteBuffer) {
        buf.putInt(value.size)
        buf.put(value)
    }
}



/**
 * Active P2P discovery session backed by the Luciola UDP broadcast engine.
 *
 * The engine announces this device's presence (`entry`), replies to probes
 * (`alive`), keeps a periodic heartbeat (`presence`), and reports every newly
 * discovered LAN peer through the `OnPeerDiscovered` callback.
 *
 * Supervision is built in so hosts do not re-implement it per platform:
 * - `node_id` is stable for the session's lifetime — engine restarts keep the
 * same identity and remote registries do not see a "new" device.
 * - `start` retries the UDP bind so a restart racing the old socket's release
 * does not silently fall back to an ephemeral port.
 * - `restart()` rebuilds the engine with the same listener (hosts call this on
 * network changes); `seconds_since_idle()` feeds host-side watchdogs.
 */
public actual open class DiscoverySession: Disposable, DiscoverySessionInterface {

    public constructor(pointer: Pointer) {
        this.pointer = pointer
        this.cleanable = UniffiLib.CLEANER.register(this, UniffiPointerDestroyer(pointer))
    }

    /**
     * This constructor can be used to instantiate a fake object. Only used for tests. Any
     * attempt to actually use an object constructed this way will fail as there is no
     * connected Rust object.
     */
    public actual constructor(noPointer: NoPointer) {
        this.pointer = null
        this.cleanable = UniffiLib.CLEANER.register(this, UniffiPointerDestroyer(null))
    }
    /**
     * Create a session announcing `name` on the given UDP discovery port.
     *
     * `manualPeers` are unicast-only targets (host:port is the UDP discovery
     * port) for peers that broadcasts cannot reach: cross-subnet hosts, VPN
     * overlays (Tailscale/ZeroTier), or localhost debugging.
     */
    public actual constructor(`name`: kotlin.String, `port`: kotlin.UShort, `manualPeers`: List<ManualPeer>?, `product`: kotlin.String?, `extra`: kotlin.String?) : this(
        uniffiRustCall { uniffiRustCallStatus ->
            UniffiLib.uniffi_luciola_uniffi_fn_constructor_discoverysession_new(
                FfiConverterString.lower(`name`),
                FfiConverterUShort.lower(`port`),
                FfiConverterOptionalSequenceTypeManualPeer.lower(`manualPeers`),
                FfiConverterOptionalString.lower(`product`),
                FfiConverterOptionalString.lower(`extra`),
                uniffiRustCallStatus,
            )
        }!!
    )

    protected val pointer: Pointer?
    protected val cleanable: UniffiCleaner.Cleanable

    private val wasDestroyed: kotlinx.atomicfu.AtomicBoolean = kotlinx.atomicfu.atomic(false)
    private val callCounter: kotlinx.atomicfu.AtomicLong = kotlinx.atomicfu.atomic(1L)

    private val lock = kotlinx.atomicfu.locks.ReentrantLock()

    private fun <T> synchronized(block: () -> T): T {
        lock.lock()
        try {
            return block()
        } finally {
            lock.unlock()
        }
    }

    actual override fun destroy() {
        // Only allow a single call to this method.
        // TODO: maybe we should log a warning if called more than once?
        if (this.wasDestroyed.compareAndSet(false, true)) {
            // This decrement always matches the initial count of 1 given at creation time.
            if (this.callCounter.decrementAndGet() == 0L) {
                cleanable.clean()
            }
        }
    }

    actual override fun close() {
        synchronized { this.destroy() }
    }

    internal inline fun <R> callWithPointer(block: (ptr: Pointer) -> R): R {
        // Check and increment the call counter, to keep the object alive.
        // This needs a compare-and-set retry loop in case of concurrent updates.
        do {
            val c = this.callCounter.value
            if (c == 0L) {
                throw IllegalStateException("${this::class::simpleName} object has already been destroyed")
            }
            if (c == Long.MAX_VALUE) {
                throw IllegalStateException("${this::class::simpleName} call counter would overflow")
            }
        } while (! this.callCounter.compareAndSet(c, c + 1L))
        // Now we can safely do the method call without the pointer being freed concurrently.
        try {
            return block(this.uniffiClonePointer())
        } finally {
            // This decrement always matches the increment we performed above.
            if (this.callCounter.decrementAndGet() == 0L) {
                cleanable.clean()
            }
        }
    }

    // Use a static inner class instead of a closure so as not to accidentally
    // capture `this` as part of the cleanable's action.
    private class UniffiPointerDestroyer(private val pointer: Pointer?) : Disposable {
        override fun destroy() {
            pointer?.let { ptr ->
                uniffiRustCall { status ->
                    UniffiLib.uniffi_luciola_uniffi_fn_free_discoverysession(ptr, status)
                }
            }
        }
    }

    public fun uniffiClonePointer(): Pointer {
        return uniffiRustCall { status ->
            UniffiLib.uniffi_luciola_uniffi_fn_clone_discoverysession(pointer!!, status)
        }!!
    }

    
    /**
     * Whether the last engine start actually bound the requested discovery
     * port. False means the port was occupied and never freed within the
     * retry window — the UI should not claim "online".
     */
    public actual override fun `isBound`(): kotlin.Boolean {
        return FfiConverterBoolean.lift(callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_discoverysession_is_bound(
                    it,
                    uniffiRustCallStatus,
                )
            }
        })
    }

    /**
     * This session's stable engine node id. Companion sockets (sweeps, unicast
     * reconciliation on the host side) should present the SAME identity so
     * remote devices see ONE node, not a duplicate peer.
     */
    public actual override fun `nodeId`(): kotlin.String {
        return FfiConverterString.lift(callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_discoverysession_node_id(
                    it,
                    uniffiRustCallStatus,
                )
            }
        })
    }

    /**
     * Stop the engine (announcing `exit` to neighbors) and rebuild it with the
     * same listener and identity. Hosts call this when the network set changes;
     * the internal bind-retry tolerates the old socket still releasing.
     */
    public actual override fun `restart`() {
        callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_discoverysession_restart(
                    it,
                    uniffiRustCallStatus,
                )
            }
        }
    }

    /**
     * Seconds since the last peer discovery (or session start). Host watchdogs
     * treat a long idle on a networked device as "engine stalled".
     */
    public actual override fun `secondsSinceIdle`(): kotlin.Double {
        return FfiConverterDouble.lift(callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_discoverysession_seconds_since_idle(
                    it,
                    uniffiRustCallStatus,
                )
            }
        })
    }

    /**
     * Replace the manual peer list; takes effect on the next `restart()`.
     */
    public actual override fun `setManualPeers`(`peers`: List<ManualPeer>) {
        callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_discoverysession_set_manual_peers(
                    it,
                    FfiConverterSequenceTypeManualPeer.lower(`peers`),
                    uniffiRustCallStatus,
                )
            }
        }
    }

    /**
     * Start the engine on a dedicated background thread.
     */
    public actual override fun `start`(`listener`: OnPeerDiscovered) {
        callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_discoverysession_start(
                    it,
                    FfiConverterTypeOnPeerDiscovered.lower(`listener`),
                    uniffiRustCallStatus,
                )
            }
        }
    }

    /**
     * Stop the session and broadcast `exit` to neighbors.
     */
    public actual override fun `stop`() {
        callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_discoverysession_stop(
                    it,
                    uniffiRustCallStatus,
                )
            }
        }
    }


    
    
    public actual companion object
    
}





public object FfiConverterTypeDiscoverySession: FfiConverter<DiscoverySession, Pointer> {

    override fun lower(value: DiscoverySession): Pointer {
        return value.uniffiClonePointer()
    }

    override fun lift(value: Pointer): DiscoverySession {
        return DiscoverySession(value)
    }

    override fun read(buf: ByteBuffer): DiscoverySession {
        // The Rust code always writes pointers as 8 bytes, and will
        // fail to compile if they don't fit.
        return lift(buf.getLong().toPointer())
    }

    override fun allocationSize(value: DiscoverySession): ULong = 8UL

    override fun write(value: DiscoverySession, buf: ByteBuffer) {
        // The Rust code always expects pointers written as 8 bytes,
        // and will fail to compile if they don't fit.
        buf.putLong(lower(value).toLong())
    }
}



/**
 * One authenticated encrypted channel (see `luciola::link::secure`).
 * Message-oriented for FFI friendliness: `send` queues an encrypted frame;
 * received frames are decrypted and delivered through the listener.
 */
public actual open class SecureSession: Disposable, SecureSessionInterface {

    public constructor(pointer: Pointer) {
        this.pointer = pointer
        this.cleanable = UniffiLib.CLEANER.register(this, UniffiPointerDestroyer(pointer))
    }

    /**
     * This constructor can be used to instantiate a fake object. Only used for tests. Any
     * attempt to actually use an object constructed this way will fail as there is no
     * connected Rust object.
     */
    public actual constructor(noPointer: NoPointer) {
        this.pointer = null
        this.cleanable = UniffiLib.CLEANER.register(this, UniffiPointerDestroyer(null))
    }
    public actual constructor(`identitySeed`: kotlin.ByteArray) : this(
        uniffiRustCall { uniffiRustCallStatus ->
            UniffiLib.uniffi_luciola_uniffi_fn_constructor_securesession_new(
                FfiConverterByteArray.lower(`identitySeed`),
                uniffiRustCallStatus,
            )
        }!!
    )

    protected val pointer: Pointer?
    protected val cleanable: UniffiCleaner.Cleanable

    private val wasDestroyed: kotlinx.atomicfu.AtomicBoolean = kotlinx.atomicfu.atomic(false)
    private val callCounter: kotlinx.atomicfu.AtomicLong = kotlinx.atomicfu.atomic(1L)

    private val lock = kotlinx.atomicfu.locks.ReentrantLock()

    private fun <T> synchronized(block: () -> T): T {
        lock.lock()
        try {
            return block()
        } finally {
            lock.unlock()
        }
    }

    actual override fun destroy() {
        // Only allow a single call to this method.
        // TODO: maybe we should log a warning if called more than once?
        if (this.wasDestroyed.compareAndSet(false, true)) {
            // This decrement always matches the initial count of 1 given at creation time.
            if (this.callCounter.decrementAndGet() == 0L) {
                cleanable.clean()
            }
        }
    }

    actual override fun close() {
        synchronized { this.destroy() }
    }

    internal inline fun <R> callWithPointer(block: (ptr: Pointer) -> R): R {
        // Check and increment the call counter, to keep the object alive.
        // This needs a compare-and-set retry loop in case of concurrent updates.
        do {
            val c = this.callCounter.value
            if (c == 0L) {
                throw IllegalStateException("${this::class::simpleName} object has already been destroyed")
            }
            if (c == Long.MAX_VALUE) {
                throw IllegalStateException("${this::class::simpleName} call counter would overflow")
            }
        } while (! this.callCounter.compareAndSet(c, c + 1L))
        // Now we can safely do the method call without the pointer being freed concurrently.
        try {
            return block(this.uniffiClonePointer())
        } finally {
            // This decrement always matches the increment we performed above.
            if (this.callCounter.decrementAndGet() == 0L) {
                cleanable.clean()
            }
        }
    }

    // Use a static inner class instead of a closure so as not to accidentally
    // capture `this` as part of the cleanable's action.
    private class UniffiPointerDestroyer(private val pointer: Pointer?) : Disposable {
        override fun destroy() {
            pointer?.let { ptr ->
                uniffiRustCall { status ->
                    UniffiLib.uniffi_luciola_uniffi_fn_free_securesession(ptr, status)
                }
            }
        }
    }

    public fun uniffiClonePointer(): Pointer {
        return uniffiRustCall { status ->
            UniffiLib.uniffi_luciola_uniffi_fn_clone_securesession(pointer!!, status)
        }!!
    }

    
    /**
     * Race-dial every candidate address (Happy Eyeballs) and run the
     * authenticated handshake on the winning socket, with a PINNED peer key.
     *
     * With `auto_reconnect` the session re-dials with exponential backoff
     * (1s..30s) whenever the channel drops, until `disconnect()`.
     */
    public actual override fun `connect`(`addresses`: List<kotlin.String>, `port`: kotlin.UShort, `pinnedPeerPublicKey`: kotlin.ByteArray, `autoReconnect`: kotlin.Boolean, `listener`: SecureSessionListener) {
        callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_securesession_connect(
                    it,
                    FfiConverterSequenceString.lower(`addresses`),
                    FfiConverterUShort.lower(`port`),
                    FfiConverterByteArray.lower(`pinnedPeerPublicKey`),
                    FfiConverterBoolean.lower(`autoReconnect`),
                    FfiConverterTypeSecureSessionListener.lower(`listener`),
                    uniffiRustCallStatus,
                )
            }
        }
    }

    /**
     * Close the channel; the peer sees the socket close. (Named
     * `disconnect` because the generated Disposable interface already owns
     * `close`.)
     */
    public actual override fun `disconnect`() {
        callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_securesession_disconnect(
                    it,
                    uniffiRustCallStatus,
                )
            }
        }
    }

    public actual override fun `isConnected`(): kotlin.Boolean {
        return FfiConverterBoolean.lift(callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_securesession_is_connected(
                    it,
                    uniffiRustCallStatus,
                )
            }
        })
    }

    /**
     * Accept connections in a LOOP (one at a time). `expected_peer`: pin the
     * peer key, or None to accept any identity (TOFU — check the reported
     * fingerprint). The listener re-arms after each channel closes.
     */
    public actual override fun `listen`(`port`: kotlin.UShort, `expectedPeer`: kotlin.ByteArray?, `listener`: SecureSessionListener) {
        callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_securesession_listen(
                    it,
                    FfiConverterUShort.lower(`port`),
                    FfiConverterOptionalByteArray.lower(`expectedPeer`),
                    FfiConverterTypeSecureSessionListener.lower(`listener`),
                    uniffiRustCallStatus,
                )
            }
        }
    }

    /**
     * Queue an encrypted frame. False when not connected OR the outbound
     * queue is full (peer stalled) — back off and retry.
     */
    public actual override fun `send`(`message`: kotlin.ByteArray): kotlin.Boolean {
        return FfiConverterBoolean.lift(callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_securesession_send(
                    it,
                    FfiConverterByteArray.lower(`message`),
                    uniffiRustCallStatus,
                )
            }
        })
    }

    /**
     * Keepalive cadence: ping after `interval_ms` idle, peer considered dead
     * after `dead_after_ms` of silence. Hosts raise both under Android Doze.
     */
    public actual override fun `setKeepalive`(`intervalMs`: kotlin.ULong, `deadAfterMs`: kotlin.ULong) {
        callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_securesession_set_keepalive(
                    it,
                    FfiConverterULong.lower(`intervalMs`),
                    FfiConverterULong.lower(`deadAfterMs`),
                    uniffiRustCallStatus,
                )
            }
        }
    }

    /**
     * Retry policy for auto-reconnect: exponential 2x from `min_ms` to
     * `max_ms`, each delay jittered by +-`jitter_pct` percent (anti-thundering-herd).
     */
    public actual override fun `setRetryPolicy`(`minMs`: kotlin.ULong, `maxMs`: kotlin.ULong, `jitterPct`: kotlin.ULong) {
        callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_securesession_set_retry_policy(
                    it,
                    FfiConverterULong.lower(`minMs`),
                    FfiConverterULong.lower(`maxMs`),
                    FfiConverterULong.lower(`jitterPct`),
                    uniffiRustCallStatus,
                )
            }
        }
    }

    /**
     * Link health counters (sent/received frames, connections, retries).
     */
    public actual override fun `stats`(): LinkStats {
        return FfiConverterTypeLinkStats.lift(callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_securesession_stats(
                    it,
                    uniffiRustCallStatus,
                )
            }
        })
    }


    
    
    public actual companion object
    
}





public object FfiConverterTypeSecureSession: FfiConverter<SecureSession, Pointer> {

    override fun lower(value: SecureSession): Pointer {
        return value.uniffiClonePointer()
    }

    override fun lift(value: Pointer): SecureSession {
        return SecureSession(value)
    }

    override fun read(buf: ByteBuffer): SecureSession {
        // The Rust code always writes pointers as 8 bytes, and will
        // fail to compile if they don't fit.
        return lift(buf.getLong().toPointer())
    }

    override fun allocationSize(value: SecureSession): ULong = 8UL

    override fun write(value: SecureSession, buf: ByteBuffer) {
        // The Rust code always expects pointers written as 8 bytes,
        // and will fail to compile if they don't fit.
        buf.putLong(lower(value).toLong())
    }
}



/**
 * Persisted trust list. Serialize with [TrustStore::to_json] and store the
 * bytes in the product's secret storage; unpaired peers are simply absent
 * (default posture: deny).
 */
public actual open class TrustStore: Disposable, TrustStoreInterface {

    public constructor(pointer: Pointer) {
        this.pointer = pointer
        this.cleanable = UniffiLib.CLEANER.register(this, UniffiPointerDestroyer(pointer))
    }

    /**
     * This constructor can be used to instantiate a fake object. Only used for tests. Any
     * attempt to actually use an object constructed this way will fail as there is no
     * connected Rust object.
     */
    public actual constructor(noPointer: NoPointer) {
        this.pointer = null
        this.cleanable = UniffiLib.CLEANER.register(this, UniffiPointerDestroyer(null))
    }
    public actual constructor(`fromJson`: kotlin.String?) : this(
        uniffiRustCall { uniffiRustCallStatus ->
            UniffiLib.uniffi_luciola_uniffi_fn_constructor_truststore_new(
                FfiConverterOptionalString.lower(`fromJson`),
                uniffiRustCallStatus,
            )
        }!!
    )

    protected val pointer: Pointer?
    protected val cleanable: UniffiCleaner.Cleanable

    private val wasDestroyed: kotlinx.atomicfu.AtomicBoolean = kotlinx.atomicfu.atomic(false)
    private val callCounter: kotlinx.atomicfu.AtomicLong = kotlinx.atomicfu.atomic(1L)

    private val lock = kotlinx.atomicfu.locks.ReentrantLock()

    private fun <T> synchronized(block: () -> T): T {
        lock.lock()
        try {
            return block()
        } finally {
            lock.unlock()
        }
    }

    actual override fun destroy() {
        // Only allow a single call to this method.
        // TODO: maybe we should log a warning if called more than once?
        if (this.wasDestroyed.compareAndSet(false, true)) {
            // This decrement always matches the initial count of 1 given at creation time.
            if (this.callCounter.decrementAndGet() == 0L) {
                cleanable.clean()
            }
        }
    }

    actual override fun close() {
        synchronized { this.destroy() }
    }

    internal inline fun <R> callWithPointer(block: (ptr: Pointer) -> R): R {
        // Check and increment the call counter, to keep the object alive.
        // This needs a compare-and-set retry loop in case of concurrent updates.
        do {
            val c = this.callCounter.value
            if (c == 0L) {
                throw IllegalStateException("${this::class::simpleName} object has already been destroyed")
            }
            if (c == Long.MAX_VALUE) {
                throw IllegalStateException("${this::class::simpleName} call counter would overflow")
            }
        } while (! this.callCounter.compareAndSet(c, c + 1L))
        // Now we can safely do the method call without the pointer being freed concurrently.
        try {
            return block(this.uniffiClonePointer())
        } finally {
            // This decrement always matches the increment we performed above.
            if (this.callCounter.decrementAndGet() == 0L) {
                cleanable.clean()
            }
        }
    }

    // Use a static inner class instead of a closure so as not to accidentally
    // capture `this` as part of the cleanable's action.
    private class UniffiPointerDestroyer(private val pointer: Pointer?) : Disposable {
        override fun destroy() {
            pointer?.let { ptr ->
                uniffiRustCall { status ->
                    UniffiLib.uniffi_luciola_uniffi_fn_free_truststore(ptr, status)
                }
            }
        }
    }

    public fun uniffiClonePointer(): Pointer {
        return uniffiRustCall { status ->
            UniffiLib.uniffi_luciola_uniffi_fn_clone_truststore(pointer!!, status)
        }!!
    }

    
    public actual override fun `entries`(): List<TrustedDeviceInfo> {
        return FfiConverterSequenceTypeTrustedDeviceInfo.lift(callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_truststore_entries(
                    it,
                    uniffiRustCallStatus,
                )
            }
        })
    }

    /**
     * Trust level for a public key; absent = unpaired.
     */
    public actual override fun `levelOf`(`publicKey`: kotlin.ByteArray): TrustLevel? {
        return FfiConverterOptionalTypeTrustLevel.lift(callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_truststore_level_of(
                    it,
                    FfiConverterByteArray.lower(`publicKey`),
                    uniffiRustCallStatus,
                )
            }
        })
    }

    /**
     * Remove a paired device by fingerprint.
     */
    public actual override fun `remove`(`fingerprint`: kotlin.String): kotlin.Boolean {
        return FfiConverterBoolean.lift(callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_truststore_remove(
                    it,
                    FfiConverterString.lower(`fingerprint`),
                    uniffiRustCallStatus,
                )
            }
        })
    }

    /**
     * JSON serialization for persistence.
     */
    public actual override fun `toJson`(): kotlin.String {
        return FfiConverterString.lift(callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_truststore_to_json(
                    it,
                    uniffiRustCallStatus,
                )
            }
        })
    }

    /**
     * Pair or re-pair a device (replaces the entry with the same public key).
     */
    public actual override fun `trustDevice`(`device`: TrustedDeviceInfo) {
        callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_truststore_trust_device(
                    it,
                    FfiConverterTypeTrustedDeviceInfo.lower(`device`),
                    uniffiRustCallStatus,
                )
            }
        }
    }


    
    
    public actual companion object
    
}





public object FfiConverterTypeTrustStore: FfiConverter<TrustStore, Pointer> {

    override fun lower(value: TrustStore): Pointer {
        return value.uniffiClonePointer()
    }

    override fun lift(value: Pointer): TrustStore {
        return TrustStore(value)
    }

    override fun read(buf: ByteBuffer): TrustStore {
        // The Rust code always writes pointers as 8 bytes, and will
        // fail to compile if they don't fit.
        return lift(buf.getLong().toPointer())
    }

    override fun allocationSize(value: TrustStore): ULong = 8UL

    override fun write(value: TrustStore, buf: ByteBuffer) {
        // The Rust code always expects pointers written as 8 bytes,
        // and will fail to compile if they don't fit.
        buf.putLong(lower(value).toLong())
    }
}




public object FfiConverterTypeDeviceIdentityInfo: FfiConverterRustBuffer<DeviceIdentityInfo> {
    override fun read(buf: ByteBuffer): DeviceIdentityInfo {
        return DeviceIdentityInfo(
            FfiConverterByteArray.read(buf),
            FfiConverterByteArray.read(buf),
            FfiConverterString.read(buf),
            FfiConverterString.read(buf),
        )
    }

    override fun allocationSize(value: DeviceIdentityInfo): ULong = (
            FfiConverterByteArray.allocationSize(value.`seed`) +
            FfiConverterByteArray.allocationSize(value.`publicKey`) +
            FfiConverterString.allocationSize(value.`fingerprint`) +
            FfiConverterString.allocationSize(value.`shortPin`)
    )

    override fun write(value: DeviceIdentityInfo, buf: ByteBuffer) {
        FfiConverterByteArray.write(value.`seed`, buf)
        FfiConverterByteArray.write(value.`publicKey`, buf)
        FfiConverterString.write(value.`fingerprint`, buf)
        FfiConverterString.write(value.`shortPin`, buf)
    }
}




public object FfiConverterTypeDeviceMeta: FfiConverterRustBuffer<DeviceMeta> {
    override fun read(buf: ByteBuffer): DeviceMeta {
        return DeviceMeta(
            FfiConverterTypeDeviceType.read(buf),
            FfiConverterString.read(buf),
            FfiConverterString.read(buf),
            FfiConverterString.read(buf),
            FfiConverterOptionalString.read(buf),
            FfiConverterOptionalString.read(buf),
        )
    }

    override fun allocationSize(value: DeviceMeta): ULong = (
            FfiConverterTypeDeviceType.allocationSize(value.`deviceType`) +
            FfiConverterString.allocationSize(value.`icon`) +
            FfiConverterString.allocationSize(value.`os`) +
            FfiConverterString.allocationSize(value.`arch`) +
            FfiConverterOptionalString.allocationSize(value.`model`) +
            FfiConverterOptionalString.allocationSize(value.`deviceId`)
    )

    override fun write(value: DeviceMeta, buf: ByteBuffer) {
        FfiConverterTypeDeviceType.write(value.`deviceType`, buf)
        FfiConverterString.write(value.`icon`, buf)
        FfiConverterString.write(value.`os`, buf)
        FfiConverterString.write(value.`arch`, buf)
        FfiConverterOptionalString.write(value.`model`, buf)
        FfiConverterOptionalString.write(value.`deviceId`, buf)
    }
}




public object FfiConverterTypeDialChannel: FfiConverterRustBuffer<DialChannel> {
    override fun read(buf: ByteBuffer): DialChannel {
        return DialChannel(
            FfiConverterString.read(buf),
            FfiConverterTypeDialStatus.read(buf),
            FfiConverterOptionalDouble.read(buf),
        )
    }

    override fun allocationSize(value: DialChannel): ULong = (
            FfiConverterString.allocationSize(value.`address`) +
            FfiConverterTypeDialStatus.allocationSize(value.`status`) +
            FfiConverterOptionalDouble.allocationSize(value.`rttMs`)
    )

    override fun write(value: DialChannel, buf: ByteBuffer) {
        FfiConverterString.write(value.`address`, buf)
        FfiConverterTypeDialStatus.write(value.`status`, buf)
        FfiConverterOptionalDouble.write(value.`rttMs`, buf)
    }
}




public object FfiConverterTypeDiscoveredPeer: FfiConverterRustBuffer<DiscoveredPeer> {
    override fun read(buf: ByteBuffer): DiscoveredPeer {
        return DiscoveredPeer(
            FfiConverterString.read(buf),
            FfiConverterString.read(buf),
            FfiConverterString.read(buf),
            FfiConverterUShort.read(buf),
            FfiConverterUShort.read(buf),
            FfiConverterOptionalTypeDeviceMeta.read(buf),
            FfiConverterOptionalString.read(buf),
            FfiConverterOptionalString.read(buf),
            FfiConverterOptionalString.read(buf),
        )
    }

    override fun allocationSize(value: DiscoveredPeer): ULong = (
            FfiConverterString.allocationSize(value.`nodeId`) +
            FfiConverterString.allocationSize(value.`name`) +
            FfiConverterString.allocationSize(value.`ip`) +
            FfiConverterUShort.allocationSize(value.`udpPort`) +
            FfiConverterUShort.allocationSize(value.`tcpPort`) +
            FfiConverterOptionalTypeDeviceMeta.allocationSize(value.`device`) +
            FfiConverterOptionalString.allocationSize(value.`deviceId`) +
            FfiConverterOptionalString.allocationSize(value.`product`) +
            FfiConverterOptionalString.allocationSize(value.`extra`)
    )

    override fun write(value: DiscoveredPeer, buf: ByteBuffer) {
        FfiConverterString.write(value.`nodeId`, buf)
        FfiConverterString.write(value.`name`, buf)
        FfiConverterString.write(value.`ip`, buf)
        FfiConverterUShort.write(value.`udpPort`, buf)
        FfiConverterUShort.write(value.`tcpPort`, buf)
        FfiConverterOptionalTypeDeviceMeta.write(value.`device`, buf)
        FfiConverterOptionalString.write(value.`deviceId`, buf)
        FfiConverterOptionalString.write(value.`product`, buf)
        FfiConverterOptionalString.write(value.`extra`, buf)
    }
}




public object FfiConverterTypeLinkStats: FfiConverterRustBuffer<LinkStats> {
    override fun read(buf: ByteBuffer): LinkStats {
        return LinkStats(
            FfiConverterULong.read(buf),
            FfiConverterULong.read(buf),
            FfiConverterULong.read(buf),
            FfiConverterULong.read(buf),
            FfiConverterULong.read(buf),
            FfiConverterULong.read(buf),
        )
    }

    override fun allocationSize(value: LinkStats): ULong = (
            FfiConverterULong.allocationSize(value.`framesSent`) +
            FfiConverterULong.allocationSize(value.`framesReceived`) +
            FfiConverterULong.allocationSize(value.`connectionsEstablished`) +
            FfiConverterULong.allocationSize(value.`reconnectAttempts`) +
            FfiConverterULong.allocationSize(value.`framesEnqueued`) +
            FfiConverterULong.allocationSize(value.`framesDequeued`)
    )

    override fun write(value: LinkStats, buf: ByteBuffer) {
        FfiConverterULong.write(value.`framesSent`, buf)
        FfiConverterULong.write(value.`framesReceived`, buf)
        FfiConverterULong.write(value.`connectionsEstablished`, buf)
        FfiConverterULong.write(value.`reconnectAttempts`, buf)
        FfiConverterULong.write(value.`framesEnqueued`, buf)
        FfiConverterULong.write(value.`framesDequeued`, buf)
    }
}




public object FfiConverterTypeManualPeer: FfiConverterRustBuffer<ManualPeer> {
    override fun read(buf: ByteBuffer): ManualPeer {
        return ManualPeer(
            FfiConverterString.read(buf),
            FfiConverterUShort.read(buf),
        )
    }

    override fun allocationSize(value: ManualPeer): ULong = (
            FfiConverterString.allocationSize(value.`host`) +
            FfiConverterUShort.allocationSize(value.`port`)
    )

    override fun write(value: ManualPeer, buf: ByteBuffer) {
        FfiConverterString.write(value.`host`, buf)
        FfiConverterUShort.write(value.`port`, buf)
    }
}




public object FfiConverterTypePairingInfo: FfiConverterRustBuffer<PairingInfo> {
    override fun read(buf: ByteBuffer): PairingInfo {
        return PairingInfo(
            FfiConverterString.read(buf),
            FfiConverterOptionalString.read(buf),
            FfiConverterUShort.read(buf),
            FfiConverterSequenceString.read(buf),
            FfiConverterOptionalString.read(buf),
            FfiConverterOptionalString.read(buf),
            FfiConverterOptionalString.read(buf),
        )
    }

    override fun allocationSize(value: PairingInfo): ULong = (
            FfiConverterString.allocationSize(value.`name`) +
            FfiConverterOptionalString.allocationSize(value.`product`) +
            FfiConverterUShort.allocationSize(value.`port`) +
            FfiConverterSequenceString.allocationSize(value.`addrs`) +
            FfiConverterOptionalString.allocationSize(value.`fingerprint`) +
            FfiConverterOptionalString.allocationSize(value.`publicKey`) +
            FfiConverterOptionalString.allocationSize(value.`pin`)
    )

    override fun write(value: PairingInfo, buf: ByteBuffer) {
        FfiConverterString.write(value.`name`, buf)
        FfiConverterOptionalString.write(value.`product`, buf)
        FfiConverterUShort.write(value.`port`, buf)
        FfiConverterSequenceString.write(value.`addrs`, buf)
        FfiConverterOptionalString.write(value.`fingerprint`, buf)
        FfiConverterOptionalString.write(value.`publicKey`, buf)
        FfiConverterOptionalString.write(value.`pin`, buf)
    }
}




public object FfiConverterTypeRaceOutcome: FfiConverterRustBuffer<RaceOutcome> {
    override fun read(buf: ByteBuffer): RaceOutcome {
        return RaceOutcome(
            FfiConverterOptionalString.read(buf),
            FfiConverterOptionalDouble.read(buf),
            FfiConverterSequenceTypeDialChannel.read(buf),
        )
    }

    override fun allocationSize(value: RaceOutcome): ULong = (
            FfiConverterOptionalString.allocationSize(value.`winner`) +
            FfiConverterOptionalDouble.allocationSize(value.`rttMs`) +
            FfiConverterSequenceTypeDialChannel.allocationSize(value.`channels`)
    )

    override fun write(value: RaceOutcome, buf: ByteBuffer) {
        FfiConverterOptionalString.write(value.`winner`, buf)
        FfiConverterOptionalDouble.write(value.`rttMs`, buf)
        FfiConverterSequenceTypeDialChannel.write(value.`channels`, buf)
    }
}




public object FfiConverterTypeTrustedDeviceInfo: FfiConverterRustBuffer<TrustedDeviceInfo> {
    override fun read(buf: ByteBuffer): TrustedDeviceInfo {
        return TrustedDeviceInfo(
            FfiConverterString.read(buf),
            FfiConverterString.read(buf),
            FfiConverterByteArray.read(buf),
            FfiConverterString.read(buf),
            FfiConverterTypeTrustLevel.read(buf),
            FfiConverterULong.read(buf),
        )
    }

    override fun allocationSize(value: TrustedDeviceInfo): ULong = (
            FfiConverterString.allocationSize(value.`deviceId`) +
            FfiConverterString.allocationSize(value.`name`) +
            FfiConverterByteArray.allocationSize(value.`publicKey`) +
            FfiConverterString.allocationSize(value.`fingerprint`) +
            FfiConverterTypeTrustLevel.allocationSize(value.`level`) +
            FfiConverterULong.allocationSize(value.`pinnedAtMs`)
    )

    override fun write(value: TrustedDeviceInfo, buf: ByteBuffer) {
        FfiConverterString.write(value.`deviceId`, buf)
        FfiConverterString.write(value.`name`, buf)
        FfiConverterByteArray.write(value.`publicKey`, buf)
        FfiConverterString.write(value.`fingerprint`, buf)
        FfiConverterTypeTrustLevel.write(value.`level`, buf)
        FfiConverterULong.write(value.`pinnedAtMs`, buf)
    }
}





public object FfiConverterTypeDeviceType: FfiConverterRustBuffer<DeviceType> {
    override fun read(buf: ByteBuffer): DeviceType = try {
        DeviceType.values()[buf.getInt() - 1]
    } catch (e: IndexOutOfBoundsException) {
        throw RuntimeException("invalid enum value, something is very wrong!!", e)
    }

    override fun allocationSize(value: DeviceType): ULong = 4UL

    override fun write(value: DeviceType, buf: ByteBuffer) {
        buf.putInt(value.ordinal + 1)
    }
}





public object FfiConverterTypeDialStatus: FfiConverterRustBuffer<DialStatus> {
    override fun read(buf: ByteBuffer): DialStatus = try {
        DialStatus.values()[buf.getInt() - 1]
    } catch (e: IndexOutOfBoundsException) {
        throw RuntimeException("invalid enum value, something is very wrong!!", e)
    }

    override fun allocationSize(value: DialStatus): ULong = 4UL

    override fun write(value: DialStatus, buf: ByteBuffer) {
        buf.putInt(value.ordinal + 1)
    }
}





public object FfiConverterTypeTrustLevel: FfiConverterRustBuffer<TrustLevel> {
    override fun read(buf: ByteBuffer): TrustLevel = try {
        TrustLevel.values()[buf.getInt() - 1]
    } catch (e: IndexOutOfBoundsException) {
        throw RuntimeException("invalid enum value, something is very wrong!!", e)
    }

    override fun allocationSize(value: TrustLevel): ULong = 4UL

    override fun write(value: TrustLevel, buf: ByteBuffer) {
        buf.putInt(value.ordinal + 1)
    }
}






// Put the implementation in an object so we don't pollute the top-level namespace
internal object uniffiCallbackInterfaceOnPeerDiscovered {
    internal object `onPeerDiscovered`: UniffiCallbackInterfaceOnPeerDiscoveredMethod0 {
        override fun callback (
            `uniffiHandle`: Long,
            `peer`: RustBufferByValue,
            `uniffiOutReturn`: Pointer,
            uniffiCallStatus: UniffiRustCallStatus,
        ) {
            val uniffiObj = FfiConverterTypeOnPeerDiscovered.handleMap.get(uniffiHandle)
            val makeCall = { ->
                uniffiObj.`onPeerDiscovered`(
                    FfiConverterTypeDiscoveredPeer.lift(`peer`),
                )
            }
            val writeReturn = { _: Unit ->
                @Suppress("UNUSED_EXPRESSION")
                uniffiOutReturn
                Unit
            }
            uniffiTraitInterfaceCall(uniffiCallStatus, makeCall, writeReturn)
        }
    }
    internal object `onPeerUpdated`: UniffiCallbackInterfaceOnPeerDiscoveredMethod1 {
        override fun callback (
            `uniffiHandle`: Long,
            `peer`: RustBufferByValue,
            `uniffiOutReturn`: Pointer,
            uniffiCallStatus: UniffiRustCallStatus,
        ) {
            val uniffiObj = FfiConverterTypeOnPeerDiscovered.handleMap.get(uniffiHandle)
            val makeCall = { ->
                uniffiObj.`onPeerUpdated`(
                    FfiConverterTypeDiscoveredPeer.lift(`peer`),
                )
            }
            val writeReturn = { _: Unit ->
                @Suppress("UNUSED_EXPRESSION")
                uniffiOutReturn
                Unit
            }
            uniffiTraitInterfaceCall(uniffiCallStatus, makeCall, writeReturn)
        }
    }
    internal object `onPeerLost`: UniffiCallbackInterfaceOnPeerDiscoveredMethod2 {
        override fun callback (
            `uniffiHandle`: Long,
            `nodeId`: RustBufferByValue,
            `uniffiOutReturn`: Pointer,
            uniffiCallStatus: UniffiRustCallStatus,
        ) {
            val uniffiObj = FfiConverterTypeOnPeerDiscovered.handleMap.get(uniffiHandle)
            val makeCall = { ->
                uniffiObj.`onPeerLost`(
                    FfiConverterString.lift(`nodeId`),
                )
            }
            val writeReturn = { _: Unit ->
                @Suppress("UNUSED_EXPRESSION")
                uniffiOutReturn
                Unit
            }
            uniffiTraitInterfaceCall(uniffiCallStatus, makeCall, writeReturn)
        }
    }
    internal object `onError`: UniffiCallbackInterfaceOnPeerDiscoveredMethod3 {
        override fun callback (
            `uniffiHandle`: Long,
            `code`: RustBufferByValue,
            `message`: RustBufferByValue,
            `uniffiOutReturn`: Pointer,
            uniffiCallStatus: UniffiRustCallStatus,
        ) {
            val uniffiObj = FfiConverterTypeOnPeerDiscovered.handleMap.get(uniffiHandle)
            val makeCall = { ->
                uniffiObj.`onError`(
                    FfiConverterString.lift(`code`),
                    FfiConverterString.lift(`message`),
                )
            }
            val writeReturn = { _: Unit ->
                @Suppress("UNUSED_EXPRESSION")
                uniffiOutReturn
                Unit
            }
            uniffiTraitInterfaceCall(uniffiCallStatus, makeCall, writeReturn)
        }
    }
    internal object uniffiFree: UniffiCallbackInterfaceFree {
        override fun callback(handle: Long) {
            FfiConverterTypeOnPeerDiscovered.handleMap.remove(handle)
        }
    }

    internal val vtable = UniffiVTableCallbackInterfaceOnPeerDiscovered(
        `onPeerDiscovered`,
        `onPeerUpdated`,
        `onPeerLost`,
        `onError`,
        uniffiFree,
    )

    internal fun register(lib: UniffiLib) {
        lib.uniffi_luciola_uniffi_fn_init_callback_vtable_onpeerdiscovered(vtable)
    }
}

public object FfiConverterTypeOnPeerDiscovered : FfiConverterCallbackInterface<OnPeerDiscovered>()






// Put the implementation in an object so we don't pollute the top-level namespace
internal object uniffiCallbackInterfaceSecureSessionListener {
    internal object `onState`: UniffiCallbackInterfaceSecureSessionListenerMethod0 {
        override fun callback (
            `uniffiHandle`: Long,
            `state`: RustBufferByValue,
            `detail`: RustBufferByValue,
            `uniffiOutReturn`: Pointer,
            uniffiCallStatus: UniffiRustCallStatus,
        ) {
            val uniffiObj = FfiConverterTypeSecureSessionListener.handleMap.get(uniffiHandle)
            val makeCall = { ->
                uniffiObj.`onState`(
                    FfiConverterString.lift(`state`),
                    FfiConverterOptionalString.lift(`detail`),
                )
            }
            val writeReturn = { _: Unit ->
                @Suppress("UNUSED_EXPRESSION")
                uniffiOutReturn
                Unit
            }
            uniffiTraitInterfaceCall(uniffiCallStatus, makeCall, writeReturn)
        }
    }
    internal object `onMessage`: UniffiCallbackInterfaceSecureSessionListenerMethod1 {
        override fun callback (
            `uniffiHandle`: Long,
            `message`: RustBufferByValue,
            `uniffiOutReturn`: Pointer,
            uniffiCallStatus: UniffiRustCallStatus,
        ) {
            val uniffiObj = FfiConverterTypeSecureSessionListener.handleMap.get(uniffiHandle)
            val makeCall = { ->
                uniffiObj.`onMessage`(
                    FfiConverterByteArray.lift(`message`),
                )
            }
            val writeReturn = { _: Unit ->
                @Suppress("UNUSED_EXPRESSION")
                uniffiOutReturn
                Unit
            }
            uniffiTraitInterfaceCall(uniffiCallStatus, makeCall, writeReturn)
        }
    }
    internal object uniffiFree: UniffiCallbackInterfaceFree {
        override fun callback(handle: Long) {
            FfiConverterTypeSecureSessionListener.handleMap.remove(handle)
        }
    }

    internal val vtable = UniffiVTableCallbackInterfaceSecureSessionListener(
        `onState`,
        `onMessage`,
        uniffiFree,
    )

    internal fun register(lib: UniffiLib) {
        lib.uniffi_luciola_uniffi_fn_init_callback_vtable_securesessionlistener(vtable)
    }
}

public object FfiConverterTypeSecureSessionListener : FfiConverterCallbackInterface<SecureSessionListener>()




public object FfiConverterOptionalULong: FfiConverterRustBuffer<kotlin.ULong?> {
    override fun read(buf: ByteBuffer): kotlin.ULong? {
        if (buf.get().toInt() == 0) {
            return null
        }
        return FfiConverterULong.read(buf)
    }

    override fun allocationSize(value: kotlin.ULong?): ULong {
        if (value == null) {
            return 1UL
        } else {
            return 1UL + FfiConverterULong.allocationSize(value)
        }
    }

    override fun write(value: kotlin.ULong?, buf: ByteBuffer) {
        if (value == null) {
            buf.put(0)
        } else {
            buf.put(1)
            FfiConverterULong.write(value, buf)
        }
    }
}




public object FfiConverterOptionalDouble: FfiConverterRustBuffer<kotlin.Double?> {
    override fun read(buf: ByteBuffer): kotlin.Double? {
        if (buf.get().toInt() == 0) {
            return null
        }
        return FfiConverterDouble.read(buf)
    }

    override fun allocationSize(value: kotlin.Double?): ULong {
        if (value == null) {
            return 1UL
        } else {
            return 1UL + FfiConverterDouble.allocationSize(value)
        }
    }

    override fun write(value: kotlin.Double?, buf: ByteBuffer) {
        if (value == null) {
            buf.put(0)
        } else {
            buf.put(1)
            FfiConverterDouble.write(value, buf)
        }
    }
}




public object FfiConverterOptionalString: FfiConverterRustBuffer<kotlin.String?> {
    override fun read(buf: ByteBuffer): kotlin.String? {
        if (buf.get().toInt() == 0) {
            return null
        }
        return FfiConverterString.read(buf)
    }

    override fun allocationSize(value: kotlin.String?): ULong {
        if (value == null) {
            return 1UL
        } else {
            return 1UL + FfiConverterString.allocationSize(value)
        }
    }

    override fun write(value: kotlin.String?, buf: ByteBuffer) {
        if (value == null) {
            buf.put(0)
        } else {
            buf.put(1)
            FfiConverterString.write(value, buf)
        }
    }
}




public object FfiConverterOptionalByteArray: FfiConverterRustBuffer<kotlin.ByteArray?> {
    override fun read(buf: ByteBuffer): kotlin.ByteArray? {
        if (buf.get().toInt() == 0) {
            return null
        }
        return FfiConverterByteArray.read(buf)
    }

    override fun allocationSize(value: kotlin.ByteArray?): ULong {
        if (value == null) {
            return 1UL
        } else {
            return 1UL + FfiConverterByteArray.allocationSize(value)
        }
    }

    override fun write(value: kotlin.ByteArray?, buf: ByteBuffer) {
        if (value == null) {
            buf.put(0)
        } else {
            buf.put(1)
            FfiConverterByteArray.write(value, buf)
        }
    }
}




public object FfiConverterOptionalTypeDeviceMeta: FfiConverterRustBuffer<DeviceMeta?> {
    override fun read(buf: ByteBuffer): DeviceMeta? {
        if (buf.get().toInt() == 0) {
            return null
        }
        return FfiConverterTypeDeviceMeta.read(buf)
    }

    override fun allocationSize(value: DeviceMeta?): ULong {
        if (value == null) {
            return 1UL
        } else {
            return 1UL + FfiConverterTypeDeviceMeta.allocationSize(value)
        }
    }

    override fun write(value: DeviceMeta?, buf: ByteBuffer) {
        if (value == null) {
            buf.put(0)
        } else {
            buf.put(1)
            FfiConverterTypeDeviceMeta.write(value, buf)
        }
    }
}




public object FfiConverterOptionalTypePairingInfo: FfiConverterRustBuffer<PairingInfo?> {
    override fun read(buf: ByteBuffer): PairingInfo? {
        if (buf.get().toInt() == 0) {
            return null
        }
        return FfiConverterTypePairingInfo.read(buf)
    }

    override fun allocationSize(value: PairingInfo?): ULong {
        if (value == null) {
            return 1UL
        } else {
            return 1UL + FfiConverterTypePairingInfo.allocationSize(value)
        }
    }

    override fun write(value: PairingInfo?, buf: ByteBuffer) {
        if (value == null) {
            buf.put(0)
        } else {
            buf.put(1)
            FfiConverterTypePairingInfo.write(value, buf)
        }
    }
}




public object FfiConverterOptionalTypeTrustLevel: FfiConverterRustBuffer<TrustLevel?> {
    override fun read(buf: ByteBuffer): TrustLevel? {
        if (buf.get().toInt() == 0) {
            return null
        }
        return FfiConverterTypeTrustLevel.read(buf)
    }

    override fun allocationSize(value: TrustLevel?): ULong {
        if (value == null) {
            return 1UL
        } else {
            return 1UL + FfiConverterTypeTrustLevel.allocationSize(value)
        }
    }

    override fun write(value: TrustLevel?, buf: ByteBuffer) {
        if (value == null) {
            buf.put(0)
        } else {
            buf.put(1)
            FfiConverterTypeTrustLevel.write(value, buf)
        }
    }
}




public object FfiConverterOptionalSequenceTypeManualPeer: FfiConverterRustBuffer<List<ManualPeer>?> {
    override fun read(buf: ByteBuffer): List<ManualPeer>? {
        if (buf.get().toInt() == 0) {
            return null
        }
        return FfiConverterSequenceTypeManualPeer.read(buf)
    }

    override fun allocationSize(value: List<ManualPeer>?): ULong {
        if (value == null) {
            return 1UL
        } else {
            return 1UL + FfiConverterSequenceTypeManualPeer.allocationSize(value)
        }
    }

    override fun write(value: List<ManualPeer>?, buf: ByteBuffer) {
        if (value == null) {
            buf.put(0)
        } else {
            buf.put(1)
            FfiConverterSequenceTypeManualPeer.write(value, buf)
        }
    }
}




public object FfiConverterSequenceString: FfiConverterRustBuffer<List<kotlin.String>> {
    override fun read(buf: ByteBuffer): List<kotlin.String> {
        val len = buf.getInt()
        return List<kotlin.String>(len) {
            FfiConverterString.read(buf)
        }
    }

    override fun allocationSize(value: List<kotlin.String>): ULong {
        val sizeForLength = 4UL
        val sizeForItems = value.sumOf { FfiConverterString.allocationSize(it) }
        return sizeForLength + sizeForItems
    }

    override fun write(value: List<kotlin.String>, buf: ByteBuffer) {
        buf.putInt(value.size)
        value.iterator().forEach {
            FfiConverterString.write(it, buf)
        }
    }
}




public object FfiConverterSequenceTypeDialChannel: FfiConverterRustBuffer<List<DialChannel>> {
    override fun read(buf: ByteBuffer): List<DialChannel> {
        val len = buf.getInt()
        return List<DialChannel>(len) {
            FfiConverterTypeDialChannel.read(buf)
        }
    }

    override fun allocationSize(value: List<DialChannel>): ULong {
        val sizeForLength = 4UL
        val sizeForItems = value.sumOf { FfiConverterTypeDialChannel.allocationSize(it) }
        return sizeForLength + sizeForItems
    }

    override fun write(value: List<DialChannel>, buf: ByteBuffer) {
        buf.putInt(value.size)
        value.iterator().forEach {
            FfiConverterTypeDialChannel.write(it, buf)
        }
    }
}




public object FfiConverterSequenceTypeManualPeer: FfiConverterRustBuffer<List<ManualPeer>> {
    override fun read(buf: ByteBuffer): List<ManualPeer> {
        val len = buf.getInt()
        return List<ManualPeer>(len) {
            FfiConverterTypeManualPeer.read(buf)
        }
    }

    override fun allocationSize(value: List<ManualPeer>): ULong {
        val sizeForLength = 4UL
        val sizeForItems = value.sumOf { FfiConverterTypeManualPeer.allocationSize(it) }
        return sizeForLength + sizeForItems
    }

    override fun write(value: List<ManualPeer>, buf: ByteBuffer) {
        buf.putInt(value.size)
        value.iterator().forEach {
            FfiConverterTypeManualPeer.write(it, buf)
        }
    }
}




public object FfiConverterSequenceTypeTrustedDeviceInfo: FfiConverterRustBuffer<List<TrustedDeviceInfo>> {
    override fun read(buf: ByteBuffer): List<TrustedDeviceInfo> {
        val len = buf.getInt()
        return List<TrustedDeviceInfo>(len) {
            FfiConverterTypeTrustedDeviceInfo.read(buf)
        }
    }

    override fun allocationSize(value: List<TrustedDeviceInfo>): ULong {
        val sizeForLength = 4UL
        val sizeForItems = value.sumOf { FfiConverterTypeTrustedDeviceInfo.allocationSize(it) }
        return sizeForLength + sizeForItems
    }

    override fun write(value: List<TrustedDeviceInfo>, buf: ByteBuffer) {
        buf.putInt(value.size)
        value.iterator().forEach {
            FfiConverterTypeTrustedDeviceInfo.write(it, buf)
        }
    }
}


/**
 * Retrieve all local addresses including VPN/tunnels (for unicast overlay sync).
 */
public actual fun `advertisedAddresses`(): List<kotlin.String> {
    return FfiConverterSequenceString.lift(uniffiRustCall { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_advertised_addresses(
            uniffiRustCallStatus,
        )
    })
}

public actual fun `buildPairingUri`(`name`: kotlin.String, `product`: kotlin.String?, `port`: kotlin.UShort, `addrs`: List<kotlin.String>, `fingerprint`: kotlin.String?, `publicKey`: kotlin.String?, `pin`: kotlin.String?): kotlin.String {
    return FfiConverterString.lift(uniffiRustCall { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_build_pairing_uri(
            FfiConverterString.lower(`name`),
            FfiConverterOptionalString.lower(`product`),
            FfiConverterUShort.lower(`port`),
            FfiConverterSequenceString.lower(`addrs`),
            FfiConverterOptionalString.lower(`fingerprint`),
            FfiConverterOptionalString.lower(`publicKey`),
            FfiConverterOptionalString.lower(`pin`),
            uniffiRustCallStatus,
        )
    })
}

/**
 * Symmetrical 6-digit on-screen comparison pin between two devices during pairing.
 */
public actual fun `comparisonPin`(`localPk`: kotlin.ByteArray, `remotePk`: kotlin.ByteArray): kotlin.String {
    return FfiConverterString.lift(uniffiRustCall { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_comparison_pin(
            FfiConverterByteArray.lower(`localPk`),
            FfiConverterByteArray.lower(`remotePk`),
            uniffiRustCallStatus,
        )
    })
}

/**
 * Selection policy shared with the demos: first 3 IPv4 candidates plus the
 * first IPv6 GUA. Feed the result into [race_connect].
 */
public actual fun `defaultRaceCandidates`(`addresses`: List<kotlin.String>): List<kotlin.String> {
    return FfiConverterSequenceString.lift(uniffiRustCall { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_default_race_candidates(
            FfiConverterSequenceString.lower(`addresses`),
            uniffiRustCallStatus,
        )
    })
}

/**
 * Generate a fresh device identity (Ed25519). Keep the seed secret.
 */
public actual fun `generateDeviceIdentity`(): DeviceIdentityInfo {
    return FfiConverterTypeDeviceIdentityInfo.lift(uniffiRustCall { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_generate_device_identity(
            uniffiRustCallStatus,
        )
    })
}

/**
 * Detect the current machine's hardware profile, OS, architecture, and form factor.
 */
public actual fun `getDeviceMeta`(): DeviceMeta {
    return FfiConverterTypeDeviceMeta.lift(uniffiRustCall { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_get_device_meta(
            uniffiRustCallStatus,
        )
    })
}

/**
 * `sha256:<hex>` fingerprint of an Ed25519 public key.
 */
public actual fun `identityFingerprint`(`publicKey`: kotlin.ByteArray): kotlin.String {
    return FfiConverterString.lift(uniffiRustCall { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_identity_fingerprint(
            FfiConverterByteArray.lower(`publicKey`),
            uniffiRustCallStatus,
        )
    })
}

/**
 * Restore an identity from a persisted 32-byte seed.
 */
public actual fun `identityFromSeed`(`seed`: kotlin.ByteArray): DeviceIdentityInfo {
    return FfiConverterTypeDeviceIdentityInfo.lift(uniffiRustCall { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_identity_from_seed(
            FfiConverterByteArray.lower(`seed`),
            uniffiRustCallStatus,
        )
    })
}

/**
 * 6-digit on-screen comparison pin for pairing.
 */
public actual fun `identityShortPin`(`publicKey`: kotlin.ByteArray): kotlin.String {
    return FfiConverterString.lift(uniffiRustCall { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_identity_short_pin(
            FfiConverterByteArray.lower(`publicKey`),
            uniffiRustCallStatus,
        )
    })
}

/**
 * Check if a peer address is in the same local network:
 * Returns true if either RFC private IPv4/IPv6 OR domestic broadband /64 GUA matching.
 */
public actual fun `isLanPeer`(`peerAddress`: kotlin.String, `localAddresses`: List<kotlin.String>): kotlin.Boolean {
    return FfiConverterBoolean.lift(uniffiRustCall { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_is_lan_peer(
            FfiConverterString.lower(`peerAddress`),
            FfiConverterSequenceString.lower(`localAddresses`),
            uniffiRustCallStatus,
        )
    })
}

/**
 * Check if an interface name looks like a real physical network interface (Wi-Fi, Ethernet).
 */
public actual fun `isPhysicalNic`(`name`: kotlin.String): kotlin.Boolean {
    return FfiConverterBoolean.lift(uniffiRustCall { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_is_physical_nic(
            FfiConverterString.lower(`name`),
            uniffiRustCallStatus,
        )
    })
}

/**
 * Check if an IP address belongs to a proxy software TUN virtual network (198.18.0.0/15).
 */
public actual fun `isTunVirtualIp`(`address`: kotlin.String): kotlin.Boolean {
    return FfiConverterBoolean.lift(uniffiRustCall { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_is_tun_virtual_ip(
            FfiConverterString.lower(`address`),
            uniffiRustCallStatus,
        )
    })
}

/**
 * Check if an interface name corresponds to a virtual adapter (utun, feth, tailscale, docker, etc.).
 */
public actual fun `isVirtualNic`(`name`: kotlin.String): kotlin.Boolean {
    return FfiConverterBoolean.lift(uniffiRustCall { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_is_virtual_nic(
            FfiConverterString.lower(`name`),
            uniffiRustCallStatus,
        )
    })
}

/**
 * Retrieve clean local candidate IP addresses (high-scoring IPv4 and domestic IPv6 GUA/ULA).
 */
public actual fun `localCandidateAddresses`(): List<kotlin.String> {
    return FfiConverterSequenceString.lift(uniffiRustCall { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_local_candidate_addresses(
            uniffiRustCallStatus,
        )
    })
}

public actual fun `parsePairingUri`(`uri`: kotlin.String): PairingInfo? {
    return FfiConverterOptionalTypePairingInfo.lift(uniffiRustCall { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_parse_pairing_uri(
            FfiConverterString.lower(`uri`),
            uniffiRustCallStatus,
        )
    })
}

/**
 * Race TCP dials across `addresses` on `port` (Happy Eyeballs): the first
 * connect wins, the rest are cancelled. Blocking; call off the UI thread.
 */
public actual fun `raceConnect`(`addresses`: List<kotlin.String>, `port`: kotlin.UShort, `attemptTimeoutMs`: kotlin.ULong?, `staggerMs`: kotlin.ULong?): RaceOutcome {
    return FfiConverterTypeRaceOutcome.lift(uniffiRustCall { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_race_connect(
            FfiConverterSequenceString.lower(`addresses`),
            FfiConverterUShort.lower(`port`),
            FfiConverterOptionalULong.lower(`attemptTimeoutMs`),
            FfiConverterOptionalULong.lower(`staggerMs`),
            uniffiRustCallStatus,
        )
    })
}

/**
 * Render a compact terminal QR code for a given URL or text content.
 *
 * In dark terminals, swaps dark and light colors so that white background border
 * and black QR modules are rendered correctly for optical scanning.
 */
public actual fun `renderQrAscii`(`content`: kotlin.String): kotlin.String? {
    return FfiConverterOptionalString.lift(uniffiRustCall { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_render_qr_ascii(
            FfiConverterString.lower(`content`),
            uniffiRustCallStatus,
        )
    })
}

/**
 * Select the best local IPv4 address for QR code / LAN access.
 */
public actual fun `selectLanIp`(): kotlin.String? {
    return FfiConverterOptionalString.lift(uniffiRustCall { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_select_lan_ip(
            uniffiRustCallStatus,
        )
    })
}

/**
 * Sign a message with a persisted seed.
 */
public actual fun `signMessage`(`seed`: kotlin.ByteArray, `message`: kotlin.ByteArray): kotlin.ByteArray {
    return FfiConverterByteArray.lift(uniffiRustCall { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_sign_message(
            FfiConverterByteArray.lower(`seed`),
            FfiConverterByteArray.lower(`message`),
            uniffiRustCallStatus,
        )
    })
}

/**
 * Retrieve per-NIC subnet broadcast addresses (e.g. `192.168.2.255`).
 *
 * These addresses bypass Clash / Sing-box TUN mode (0.0.0.0/1) route capture.
 */
public actual fun `subnetBroadcastAddresses`(): List<kotlin.String> {
    return FfiConverterSequenceString.lift(uniffiRustCall { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_subnet_broadcast_addresses(
            uniffiRustCallStatus,
        )
    })
}

/**
 * Verify a signature against an Ed25519 public key.
 */
public actual fun `verifyMessage`(`publicKey`: kotlin.ByteArray, `message`: kotlin.ByteArray, `signature`: kotlin.ByteArray): kotlin.Boolean {
    return FfiConverterBoolean.lift(uniffiRustCall { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_verify_message(
            FfiConverterByteArray.lower(`publicKey`),
            FfiConverterByteArray.lower(`message`),
            FfiConverterByteArray.lower(`signature`),
            uniffiRustCallStatus,
        )
    })
}


// Async support