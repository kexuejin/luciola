

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
internal interface UniffiCallbackInterfaceHubEventListenerMethod0: com.sun.jna.Callback {
    public fun callback(`uniffiHandle`: Long,`peer`: RustBufferByValue,`uniffiOutReturn`: Pointer,uniffiCallStatus: UniffiRustCallStatus,)
}
internal interface UniffiCallbackInterfaceHubEventListenerMethod1: com.sun.jna.Callback {
    public fun callback(`uniffiHandle`: Long,`fingerprint`: RustBufferByValue,`remoteAddr`: RustBufferByValue,`payload`: RustBufferByValue,`uniffiOutReturn`: Pointer,uniffiCallStatus: UniffiRustCallStatus,)
}
internal interface UniffiCallbackInterfaceHubEventListenerMethod2: com.sun.jna.Callback {
    public fun callback(`uniffiHandle`: Long,`fingerprint`: RustBufferByValue,`uniffiOutReturn`: Pointer,uniffiCallStatus: UniffiRustCallStatus,)
}
internal interface UniffiCallbackInterfaceHubEventListenerMethod3: com.sun.jna.Callback {
    public fun callback(`uniffiHandle`: Long,`remoteAddr`: RustBufferByValue,`reason`: RustBufferByValue,`uniffiOutReturn`: Pointer,uniffiCallStatus: UniffiRustCallStatus,)
}
internal interface UniffiCallbackInterfaceLogSinkMethod0: com.sun.jna.Callback {
    public fun callback(`uniffiHandle`: Long,`level`: RustBufferByValue,`message`: RustBufferByValue,`uniffiOutReturn`: Pointer,uniffiCallStatus: UniffiRustCallStatus,)
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
    public fun callback(`uniffiHandle`: Long,`message`: RustBufferByValue,`peerFingerprint`: RustBufferByValue,`remoteAddr`: RustBufferByValue,`uniffiOutReturn`: Pointer,uniffiCallStatus: UniffiRustCallStatus,)
}
internal interface UniffiCallbackInterfaceTransferListenerMethod0: com.sun.jna.Callback {
    public fun callback(`uniffiHandle`: Long,`progress`: RustBufferByValue,`uniffiOutReturn`: Pointer,uniffiCallStatus: UniffiRustCallStatus,)
}
@Structure.FieldOrder("onPeerConnected", "onMessage", "onPeerDisconnected", "onPeerRejected", "uniffiFree")
internal open class UniffiVTableCallbackInterfaceHubEventListenerStruct(
    @JvmField public var `onPeerConnected`: UniffiCallbackInterfaceHubEventListenerMethod0?,
    @JvmField public var `onMessage`: UniffiCallbackInterfaceHubEventListenerMethod1?,
    @JvmField public var `onPeerDisconnected`: UniffiCallbackInterfaceHubEventListenerMethod2?,
    @JvmField public var `onPeerRejected`: UniffiCallbackInterfaceHubEventListenerMethod3?,
    @JvmField public var `uniffiFree`: UniffiCallbackInterfaceFree?,
) : com.sun.jna.Structure() {
    internal constructor(): this(
        
        `onPeerConnected` = null,
        
        `onMessage` = null,
        
        `onPeerDisconnected` = null,
        
        `onPeerRejected` = null,
        
        `uniffiFree` = null,
        
    )

    internal class UniffiByValue(
        `onPeerConnected`: UniffiCallbackInterfaceHubEventListenerMethod0?,
        `onMessage`: UniffiCallbackInterfaceHubEventListenerMethod1?,
        `onPeerDisconnected`: UniffiCallbackInterfaceHubEventListenerMethod2?,
        `onPeerRejected`: UniffiCallbackInterfaceHubEventListenerMethod3?,
        `uniffiFree`: UniffiCallbackInterfaceFree?,
    ): UniffiVTableCallbackInterfaceHubEventListener(`onPeerConnected`,`onMessage`,`onPeerDisconnected`,`onPeerRejected`,`uniffiFree`,), Structure.ByValue
}

internal typealias UniffiVTableCallbackInterfaceHubEventListener = UniffiVTableCallbackInterfaceHubEventListenerStruct

internal fun UniffiVTableCallbackInterfaceHubEventListener.uniffiSetValue(other: UniffiVTableCallbackInterfaceHubEventListener) {
    `onPeerConnected` = other.`onPeerConnected`
    `onMessage` = other.`onMessage`
    `onPeerDisconnected` = other.`onPeerDisconnected`
    `onPeerRejected` = other.`onPeerRejected`
    `uniffiFree` = other.`uniffiFree`
}
internal fun UniffiVTableCallbackInterfaceHubEventListener.uniffiSetValue(other: UniffiVTableCallbackInterfaceHubEventListenerUniffiByValue) {
    `onPeerConnected` = other.`onPeerConnected`
    `onMessage` = other.`onMessage`
    `onPeerDisconnected` = other.`onPeerDisconnected`
    `onPeerRejected` = other.`onPeerRejected`
    `uniffiFree` = other.`uniffiFree`
}

internal typealias UniffiVTableCallbackInterfaceHubEventListenerUniffiByValue = UniffiVTableCallbackInterfaceHubEventListenerStruct.UniffiByValue
@Structure.FieldOrder("log", "uniffiFree")
internal open class UniffiVTableCallbackInterfaceLogSinkStruct(
    @JvmField public var `log`: UniffiCallbackInterfaceLogSinkMethod0?,
    @JvmField public var `uniffiFree`: UniffiCallbackInterfaceFree?,
) : com.sun.jna.Structure() {
    internal constructor(): this(
        
        `log` = null,
        
        `uniffiFree` = null,
        
    )

    internal class UniffiByValue(
        `log`: UniffiCallbackInterfaceLogSinkMethod0?,
        `uniffiFree`: UniffiCallbackInterfaceFree?,
    ): UniffiVTableCallbackInterfaceLogSink(`log`,`uniffiFree`,), Structure.ByValue
}

internal typealias UniffiVTableCallbackInterfaceLogSink = UniffiVTableCallbackInterfaceLogSinkStruct

internal fun UniffiVTableCallbackInterfaceLogSink.uniffiSetValue(other: UniffiVTableCallbackInterfaceLogSink) {
    `log` = other.`log`
    `uniffiFree` = other.`uniffiFree`
}
internal fun UniffiVTableCallbackInterfaceLogSink.uniffiSetValue(other: UniffiVTableCallbackInterfaceLogSinkUniffiByValue) {
    `log` = other.`log`
    `uniffiFree` = other.`uniffiFree`
}

internal typealias UniffiVTableCallbackInterfaceLogSinkUniffiByValue = UniffiVTableCallbackInterfaceLogSinkStruct.UniffiByValue
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
@Structure.FieldOrder("onProgress", "uniffiFree")
internal open class UniffiVTableCallbackInterfaceTransferListenerStruct(
    @JvmField public var `onProgress`: UniffiCallbackInterfaceTransferListenerMethod0?,
    @JvmField public var `uniffiFree`: UniffiCallbackInterfaceFree?,
) : com.sun.jna.Structure() {
    internal constructor(): this(
        
        `onProgress` = null,
        
        `uniffiFree` = null,
        
    )

    internal class UniffiByValue(
        `onProgress`: UniffiCallbackInterfaceTransferListenerMethod0?,
        `uniffiFree`: UniffiCallbackInterfaceFree?,
    ): UniffiVTableCallbackInterfaceTransferListener(`onProgress`,`uniffiFree`,), Structure.ByValue
}

internal typealias UniffiVTableCallbackInterfaceTransferListener = UniffiVTableCallbackInterfaceTransferListenerStruct

internal fun UniffiVTableCallbackInterfaceTransferListener.uniffiSetValue(other: UniffiVTableCallbackInterfaceTransferListener) {
    `onProgress` = other.`onProgress`
    `uniffiFree` = other.`uniffiFree`
}
internal fun UniffiVTableCallbackInterfaceTransferListener.uniffiSetValue(other: UniffiVTableCallbackInterfaceTransferListenerUniffiByValue) {
    `onProgress` = other.`onProgress`
    `uniffiFree` = other.`uniffiFree`
}

internal typealias UniffiVTableCallbackInterfaceTransferListenerUniffiByValue = UniffiVTableCallbackInterfaceTransferListenerStruct.UniffiByValue



















































































































































































































































































































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
        if (uniffi_luciola_uniffi_checksum_func_build_pairing_uri() != 27091.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_build_pairing_uri_v3() != 30826.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_classify_error() != 40540.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_comparison_pin() != 2657.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_connect_wan() != 30765.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_connect_with_policy() != 35820.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_default_race_candidates() != 52364.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_derive_rendezvous_room_id() != 8384.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_error_codes() != 47804.toShort()) {
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
        if (uniffi_luciola_uniffi_checksum_func_parse_pairing_uri() != 46692.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_race_connect() != 26451.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_relay_aead_open() != 49296.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_relay_aead_seal() != 36240.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_relay_ephemeral_keypair() != 39083.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_relay_ephemeral_public() != 33732.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_relay_hkdf_sha256() != 38170.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_relay_session_keys() != 3342.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_relay_signed_handshake_payload() != 25663.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_relay_transcript_hash() != 110.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_render_qr_ascii() != 34654.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_select_lan_ip() != 61023.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_set_log_sink() != 14223.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_sign_message() != 47227.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_subnet_broadcast_addresses() != 6105.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_transfer_recv_lan() != 52444.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_transfer_recv_wan() != 50333.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_transfer_send_lan() != 57051.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_transfer_send_wan() != 33149.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_verify_message() != 57140.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_wan_current_epoch() != 42078.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_func_wan_derive_room_id() != 57681.toShort()) {
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
        if (uniffi_luciola_uniffi_checksum_method_discoverysession_set_product_filter() != 64489.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_discoverysession_start() != 53880.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_discoverysession_stop() != 1480.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securehub_add_allowed_peer() != 50106.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securehub_broadcast() != 35669.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securehub_connected_peers() != 16789.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securehub_kick() != 36514.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securehub_local_addr() != 51642.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securehub_local_port() != 17492.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securehub_remove_allowed_peer() != 60786.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securehub_send_to() != 59826.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securehub_stop() != 34084.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securesession_attach_wan_channel() != 65072.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securesession_closecurrentchannel() != 43852.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securesession_connect() != 30869.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securesession_disable_forward_endpoint() != 35699.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securesession_disable_remote_endpoint() != 10815.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securesession_disconnect() != 52412.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securesession_enable_forward_endpoint() != 14717.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securesession_enable_remote_endpoint() != 65037.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securesession_forward_stats() != 30122.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securesession_is_connected() != 48101.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securesession_listen() != 14622.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securesession_peerpublickey() != 47645.toShort()) {
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
        if (uniffi_luciola_uniffi_checksum_method_securesession_set_tunnel_keepalive() != 1419.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securesession_set_tunnel_port() != 4575.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securesession_start_local_forward() != 51827.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securesession_start_remote_forward() != 22878.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securesession_start_udp_forward() != 27128.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securesession_stats() != 9425.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securesession_stop_local_forward() != 21454.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securesession_stop_remote_forward() != 42058.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securesession_stop_udp_forward() != 19408.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_transfercancelhandle_cancel() != 48631.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_transfercancelhandle_is_cancelled() != 28569.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_truststore_entries() != 48483.toShort()) {
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
        if (uniffi_luciola_uniffi_checksum_method_wanchannel_channel_type() != 18386.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_wanchannel_remote_addr() != 46558.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_wanchannel_shutdown() != 26295.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_wantunnelsession_channel_type() != 15028.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_wantunnelsession_disable_forward_endpoint() != 38116.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_wantunnelsession_enable_forward_endpoint() != 21219.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_wantunnelsession_is_alive() != 25609.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_wantunnelsession_shutdown() != 44211.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_wantunnelsession_start_local_forward() != 25028.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_wantunnelsession_start_udp_forward() != 63004.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_wantunnelsession_stats() != 40911.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_wantunnelsession_stop_local_forward() != 19788.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_wantunnelsession_stop_udp_forward() != 16388.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_constructor_discoverysession_new() != 49533.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_constructor_securehub_start() != 17026.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_constructor_securesession_new() != 15751.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_constructor_transfercancelhandle_new() != 59042.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_constructor_truststore_new() != 36036.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_constructor_wantunnelsession_from_wan_channel() != 43571.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_hubeventlistener_on_peer_connected() != 8661.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_hubeventlistener_on_message() != 52361.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_hubeventlistener_on_peer_disconnected() != 58039.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_hubeventlistener_on_peer_rejected() != 47150.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_logsink_log() != 26187.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_onpeerdiscovered_on_peer_discovered() != 64667.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_onpeerdiscovered_on_peer_updated() != 20150.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_onpeerdiscovered_on_peer_lost() != 2979.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_onpeerdiscovered_on_error() != 7804.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securesessionlistener_on_state() != 43161.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_securesessionlistener_on_message() != 63088.toShort()) {
            throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
        }
        if (uniffi_luciola_uniffi_checksum_method_transferlistener_on_progress() != 3422.toShort()) {
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
    external fun uniffi_luciola_uniffi_checksum_func_build_pairing_uri_v3(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_classify_error(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_comparison_pin(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_connect_wan(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_connect_with_policy(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_default_race_candidates(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_derive_rendezvous_room_id(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_error_codes(
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
    external fun uniffi_luciola_uniffi_checksum_func_relay_aead_open(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_relay_aead_seal(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_relay_ephemeral_keypair(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_relay_ephemeral_public(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_relay_hkdf_sha256(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_relay_session_keys(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_relay_signed_handshake_payload(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_relay_transcript_hash(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_render_qr_ascii(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_select_lan_ip(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_set_log_sink(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_sign_message(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_subnet_broadcast_addresses(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_transfer_recv_lan(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_transfer_recv_wan(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_transfer_send_lan(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_transfer_send_wan(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_verify_message(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_wan_current_epoch(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_func_wan_derive_room_id(
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
    external fun uniffi_luciola_uniffi_checksum_method_discoverysession_set_product_filter(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_discoverysession_start(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_discoverysession_stop(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securehub_add_allowed_peer(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securehub_broadcast(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securehub_connected_peers(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securehub_kick(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securehub_local_addr(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securehub_local_port(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securehub_remove_allowed_peer(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securehub_send_to(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securehub_stop(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securesession_attach_wan_channel(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securesession_closecurrentchannel(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securesession_connect(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securesession_disable_forward_endpoint(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securesession_disable_remote_endpoint(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securesession_disconnect(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securesession_enable_forward_endpoint(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securesession_enable_remote_endpoint(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securesession_forward_stats(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securesession_is_connected(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securesession_listen(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securesession_peerpublickey(
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
    external fun uniffi_luciola_uniffi_checksum_method_securesession_set_tunnel_keepalive(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securesession_set_tunnel_port(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securesession_start_local_forward(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securesession_start_remote_forward(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securesession_start_udp_forward(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securesession_stats(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securesession_stop_local_forward(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securesession_stop_remote_forward(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_securesession_stop_udp_forward(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_transfercancelhandle_cancel(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_transfercancelhandle_is_cancelled(
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
    external fun uniffi_luciola_uniffi_checksum_method_wanchannel_channel_type(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_wanchannel_remote_addr(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_wanchannel_shutdown(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_wantunnelsession_channel_type(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_wantunnelsession_disable_forward_endpoint(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_wantunnelsession_enable_forward_endpoint(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_wantunnelsession_is_alive(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_wantunnelsession_shutdown(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_wantunnelsession_start_local_forward(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_wantunnelsession_start_udp_forward(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_wantunnelsession_stats(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_wantunnelsession_stop_local_forward(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_wantunnelsession_stop_udp_forward(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_constructor_discoverysession_new(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_constructor_securehub_start(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_constructor_securesession_new(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_constructor_transfercancelhandle_new(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_constructor_truststore_new(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_constructor_wantunnelsession_from_wan_channel(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_hubeventlistener_on_peer_connected(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_hubeventlistener_on_message(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_hubeventlistener_on_peer_disconnected(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_hubeventlistener_on_peer_rejected(
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_checksum_method_logsink_log(
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
    external fun uniffi_luciola_uniffi_checksum_method_transferlistener_on_progress(
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
        uniffiCallbackInterfaceHubEventListener.register(this)
        uniffiCallbackInterfaceLogSink.register(this)
        uniffiCallbackInterfaceOnPeerDiscovered.register(this)
        uniffiCallbackInterfaceSecureSessionListener.register(this)
        uniffiCallbackInterfaceTransferListener.register(this)
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
        `nodeId`: RustBufferByValue,
        `tcpPort`: RustBufferByValue,
        `publicKey`: RustBufferByValue,
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
    external fun uniffi_luciola_uniffi_fn_method_discoverysession_set_product_filter(
        `ptr`: Pointer?,
        `products`: RustBufferByValue,
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
    external fun uniffi_luciola_uniffi_fn_clone_securehub(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Pointer?
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_free_securehub(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_constructor_securehub_start(
        `port`: Short,
        `identitySeed`: RustBufferByValue,
        `allowedPeerPublicKeys`: RustBufferByValue,
        `listener`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Pointer?
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_securehub_add_allowed_peer(
        `ptr`: Pointer?,
        `publicKey`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_securehub_broadcast(
        `ptr`: Pointer?,
        `payload`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_securehub_connected_peers(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_securehub_kick(
        `ptr`: Pointer?,
        `fingerprint`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_securehub_local_addr(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_securehub_local_port(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_securehub_remove_allowed_peer(
        `ptr`: Pointer?,
        `publicKey`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_securehub_send_to(
        `ptr`: Pointer?,
        `fingerprint`: RustBufferByValue,
        `payload`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_securehub_stop(
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
    external fun uniffi_luciola_uniffi_fn_method_securesession_attach_wan_channel(
        `ptr`: Pointer?,
        `channel`: Pointer?,
        `listener`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_securesession_closecurrentchannel(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit
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
    external fun uniffi_luciola_uniffi_fn_method_securesession_disable_forward_endpoint(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_securesession_disable_remote_endpoint(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_securesession_disconnect(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_securesession_enable_forward_endpoint(
        `ptr`: Pointer?,
        `rules`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_securesession_enable_remote_endpoint(
        `ptr`: Pointer?,
        `rules`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_securesession_forward_stats(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
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
    external fun uniffi_luciola_uniffi_fn_method_securesession_peerpublickey(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
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
    external fun uniffi_luciola_uniffi_fn_method_securesession_set_tunnel_keepalive(
        `ptr`: Pointer?,
        `intervalMs`: Long,
        `deadAfterMs`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_securesession_set_tunnel_port(
        `ptr`: Pointer?,
        `port`: Short,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_securesession_start_local_forward(
        `ptr`: Pointer?,
        `listenPort`: Short,
        `host`: RustBufferByValue,
        `port`: Short,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_securesession_start_remote_forward(
        `ptr`: Pointer?,
        `listenPort`: Short,
        `host`: RustBufferByValue,
        `port`: Short,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_securesession_start_udp_forward(
        `ptr`: Pointer?,
        `listenPort`: Short,
        `host`: RustBufferByValue,
        `port`: Short,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_securesession_stats(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_securesession_stop_local_forward(
        `ptr`: Pointer?,
        `listenPort`: Short,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_securesession_stop_remote_forward(
        `ptr`: Pointer?,
        `listenPort`: Short,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_securesession_stop_udp_forward(
        `ptr`: Pointer?,
        `listenPort`: Short,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_clone_transfercancelhandle(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Pointer?
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_free_transfercancelhandle(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_constructor_transfercancelhandle_new(
        uniffiCallStatus: UniffiRustCallStatus,
    ): Pointer?
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_transfercancelhandle_cancel(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_transfercancelhandle_is_cancelled(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte
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
    external fun uniffi_luciola_uniffi_fn_clone_wanchannel(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Pointer?
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_free_wanchannel(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_wanchannel_channel_type(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_wanchannel_remote_addr(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_wanchannel_shutdown(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_clone_wantunnelsession(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Pointer?
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_free_wantunnelsession(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_constructor_wantunnelsession_from_wan_channel(
        `channel`: Pointer?,
        `isInitiator`: Byte,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Pointer?
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_wantunnelsession_channel_type(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_wantunnelsession_disable_forward_endpoint(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_wantunnelsession_enable_forward_endpoint(
        `ptr`: Pointer?,
        `rules`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_wantunnelsession_is_alive(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_wantunnelsession_shutdown(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_wantunnelsession_start_local_forward(
        `ptr`: Pointer?,
        `listenPort`: Short,
        `host`: RustBufferByValue,
        `port`: Short,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_wantunnelsession_start_udp_forward(
        `ptr`: Pointer?,
        `listenPort`: Short,
        `host`: RustBufferByValue,
        `port`: Short,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Short
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_wantunnelsession_stats(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_wantunnelsession_stop_local_forward(
        `ptr`: Pointer?,
        `listenPort`: Short,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_method_wantunnelsession_stop_udp_forward(
        `ptr`: Pointer?,
        `listenPort`: Short,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_init_callback_vtable_hubeventlistener(
        `vtable`: UniffiVTableCallbackInterfaceHubEventListener,
    ): Unit
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_init_callback_vtable_logsink(
        `vtable`: UniffiVTableCallbackInterfaceLogSink,
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
    external fun uniffi_luciola_uniffi_fn_init_callback_vtable_transferlistener(
        `vtable`: UniffiVTableCallbackInterfaceTransferListener,
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
    external fun uniffi_luciola_uniffi_fn_func_build_pairing_uri_v3(
        `name`: RustBufferByValue,
        `product`: RustBufferByValue,
        `port`: Short,
        `addrs`: RustBufferByValue,
        `fingerprint`: RustBufferByValue,
        `publicKey`: RustBufferByValue,
        `pin`: RustBufferByValue,
        `psk`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_classify_error(
        `codeOrDetail`: RustBufferByValue,
        `message`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_comparison_pin(
        `localPk`: RustBufferByValue,
        `remotePk`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_connect_wan(
        `config`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Pointer?
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_connect_with_policy(
        `policy`: RustBufferByValue,
        `lanBudgetMs`: Long,
        `lan`: RustBufferByValue,
        `wan`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Pointer?
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_default_race_candidates(
        `addresses`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_derive_rendezvous_room_id(
        `myPk`: RustBufferByValue,
        `peerPk`: RustBufferByValue,
        `psk`: RustBufferByValue,
        `epoch`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_error_codes(
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
    external fun uniffi_luciola_uniffi_fn_func_relay_aead_open(
        `key`: RustBufferByValue,
        `seq`: Long,
        `aad`: RustBufferByValue,
        `ciphertext`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_relay_aead_seal(
        `key`: RustBufferByValue,
        `seq`: Long,
        `aad`: RustBufferByValue,
        `plaintext`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_relay_ephemeral_keypair(
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_relay_ephemeral_public(
        `secret`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_relay_hkdf_sha256(
        `ikm`: RustBufferByValue,
        `salt`: RustBufferByValue,
        `info`: RustBufferByValue,
        `outLen`: Int,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_relay_session_keys(
        `ephemeralSecret`: RustBufferByValue,
        `peerEphemeralPublic`: RustBufferByValue,
        `transcript`: RustBufferByValue,
        `initiatorFingerprint`: RustBufferByValue,
        `responderFingerprint`: RustBufferByValue,
        `isInitiator`: Byte,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_relay_signed_handshake_payload(
        `timestampMs`: Long,
        `nodeId`: RustBufferByValue,
        `ephemeralPublic`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_relay_transcript_hash(
        `initiatorHandshake`: RustBufferByValue,
        `responderHandshake`: RustBufferByValue,
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
    external fun uniffi_luciola_uniffi_fn_func_set_log_sink(
        `sink`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit
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
    external fun uniffi_luciola_uniffi_fn_func_transfer_recv_lan(
        `identitySeed`: RustBufferByValue,
        `listenPort`: Short,
        `acceptPeerPublicKey`: RustBufferByValue,
        `destDir`: RustBufferByValue,
        `listener`: RustBufferByValue,
        `cancel`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_transfer_recv_wan(
        `channel`: Pointer?,
        `destDir`: RustBufferByValue,
        `listener`: RustBufferByValue,
        `cancel`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_transfer_send_lan(
        `identitySeed`: RustBufferByValue,
        `addresses`: RustBufferByValue,
        `port`: Short,
        `pinnedPeerPublicKey`: RustBufferByValue,
        `filePath`: RustBufferByValue,
        `listener`: RustBufferByValue,
        `cancel`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_transfer_send_wan(
        `channel`: Pointer?,
        `filePath`: RustBufferByValue,
        `maxRelayBytes`: RustBufferByValue,
        `listener`: RustBufferByValue,
        `cancel`: RustBufferByValue,
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
    external fun uniffi_luciola_uniffi_fn_func_wan_current_epoch(
        uniffiCallStatus: UniffiRustCallStatus,
    ): Long
    @JvmStatic
    external fun uniffi_luciola_uniffi_fn_func_wan_derive_room_id(
        `myPublicKey`: RustBufferByValue,
        `peerPublicKey`: RustBufferByValue,
        `psk`: RustBufferByValue,
        `epoch`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue
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


public object FfiConverterUInt: FfiConverter<UInt, Int> {
    override fun lift(value: Int): UInt {
        return value.toUInt()
    }

    override fun read(buf: ByteBuffer): UInt {
        return lift(buf.getInt())
    }

    override fun lower(value: UInt): Int {
        return value.toInt()
    }

    override fun allocationSize(value: UInt): ULong = 4UL

    override fun write(value: UInt, buf: ByteBuffer) {
        buf.putInt(value.toInt())
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
     *
     * `node_id`, `tcp_port` and `public_key` let the host pin the beacon's
     * identity to ITS OWN key material (zero-trust pairing wants the
     * advertised Ed25519 key to match the one the secure channel presents);
     * pass `None` to let the engine generate them.
     */
    public actual constructor(`name`: kotlin.String, `port`: kotlin.UShort, `manualPeers`: List<ManualPeer>?, `product`: kotlin.String?, `extra`: kotlin.String?, `nodeId`: kotlin.String?, `tcpPort`: kotlin.UShort?, `publicKey`: kotlin.ByteArray?) : this(
        uniffiRustCall { uniffiRustCallStatus ->
            UniffiLib.uniffi_luciola_uniffi_fn_constructor_discoverysession_new(
                FfiConverterString.lower(`name`),
                FfiConverterUShort.lower(`port`),
                FfiConverterOptionalSequenceTypeManualPeer.lower(`manualPeers`),
                FfiConverterOptionalString.lower(`product`),
                FfiConverterOptionalString.lower(`extra`),
                FfiConverterOptionalString.lower(`nodeId`),
                FfiConverterOptionalUShort.lower(`tcpPort`),
                FfiConverterOptionalByteArray.lower(`publicKey`),
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
     * Restrict discovery to these `Profile.product` labels.
     *
     * `None` or an empty list accepts every product (the historical open
     * mesh). Takes effect on the next `start()` / `restart()`. Use it when
     * several luciola products share one discovery port or one machine:
     * without a filter each product sees the others as peers and dials the
     * channel port advertised in their profiles (the 2026-11-02 cross-dial).
     */
    public actual override fun `setProductFilter`(`products`: List<kotlin.String>?) {
        callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_discoverysession_set_product_filter(
                    it,
                    FfiConverterOptionalSequenceString.lower(`products`),
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
 * Concurrent multi-peer authenticated TCP server on a single dual-stack port.
 *
 * Peer keys are checked against an explicit allowlist **before** the server signs
 * handshake message 2 (deny by default; untrusted initiators learn neither the hub's
 * public key nor any signature).
 */
public actual open class SecureHub: Disposable, SecureHubInterface {

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
                    UniffiLib.uniffi_luciola_uniffi_fn_free_securehub(ptr, status)
                }
            }
        }
    }

    public fun uniffiClonePointer(): Pointer {
        return uniffiRustCall { status ->
            UniffiLib.uniffi_luciola_uniffi_fn_clone_securehub(pointer!!, status)
        }!!
    }

    
    /**
     * Add a 32-byte Ed25519 peer public key to the pre-sign allowlist.
     * Returns `true` if newly added, `false` if already present.
     */
    @Throws(WanFfiException::class)
    public actual override fun `addAllowedPeer`(`publicKey`: kotlin.ByteArray): kotlin.Boolean {
        return FfiConverterBoolean.lift(callWithPointer {
            uniffiRustCallWithError(WanFfiExceptionErrorHandler) { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_securehub_add_allowed_peer(
                    it,
                    FfiConverterByteArray.lower(`publicKey`),
                    uniffiRustCallStatus,
                )
            }
        })
    }

    /**
     * Broadcast an encrypted frame to every connected peer.
     * Returns fingerprints whose outbound queue rejected the frame.
     */
    public actual override fun `broadcast`(`payload`: kotlin.ByteArray): List<kotlin.String> {
        return FfiConverterSequenceString.lift(callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_securehub_broadcast(
                    it,
                    FfiConverterByteArray.lower(`payload`),
                    uniffiRustCallStatus,
                )
            }
        })
    }

    /**
     * Snapshot of currently connected peers.
     */
    public actual override fun `connectedPeers`(): List<HubPeerInfoDto> {
        return FfiConverterSequenceTypeHubPeerInfoDto.lift(callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_securehub_connected_peers(
                    it,
                    uniffiRustCallStatus,
                )
            }
        })
    }

    /**
     * Disconnect one connected peer by fingerprint and emit `on_peer_disconnected`.
     */
    public actual override fun `kick`(`fingerprint`: kotlin.String): kotlin.Boolean {
        return FfiConverterBoolean.lift(callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_securehub_kick(
                    it,
                    FfiConverterString.lower(`fingerprint`),
                    uniffiRustCallStatus,
                )
            }
        })
    }

    /**
     * Actual listening socket address (`ip:port`).
     */
    public actual override fun `localAddr`(): kotlin.String {
        return FfiConverterString.lift(callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_securehub_local_addr(
                    it,
                    uniffiRustCallStatus,
                )
            }
        })
    }

    /**
     * Actual listening TCP port (useful when started with `port == 0`).
     */
    public actual override fun `localPort`(): kotlin.UShort {
        return FfiConverterUShort.lift(callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_securehub_local_port(
                    it,
                    uniffiRustCallStatus,
                )
            }
        })
    }

    /**
     * Remove a 32-byte Ed25519 peer public key from the pre-sign allowlist.
     * Does not disconnect an already-connected session; call [`Self::kick`] to drop an active peer.
     */
    @Throws(WanFfiException::class)
    public actual override fun `removeAllowedPeer`(`publicKey`: kotlin.ByteArray): kotlin.Boolean {
        return FfiConverterBoolean.lift(callWithPointer {
            uniffiRustCallWithError(WanFfiExceptionErrorHandler) { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_securehub_remove_allowed_peer(
                    it,
                    FfiConverterByteArray.lower(`publicKey`),
                    uniffiRustCallStatus,
                )
            }
        })
    }

    /**
     * Queue an encrypted frame for one connected peer (`false` if disconnected or backpressured).
     */
    public actual override fun `sendTo`(`fingerprint`: kotlin.String, `payload`: kotlin.ByteArray): kotlin.Boolean {
        return FfiConverterBoolean.lift(callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_securehub_send_to(
                    it,
                    FfiConverterString.lower(`fingerprint`),
                    FfiConverterByteArray.lower(`payload`),
                    uniffiRustCallStatus,
                )
            }
        })
    }

    /**
     * Stop accepting new peers and disconnect every active peer. Idempotent.
     */
    public actual override fun `stop`() {
        callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_securehub_stop(
                    it,
                    uniffiRustCallStatus,
                )
            }
        }
    }


    
    public actual companion object {
        
        /**
         * Bind `port` (`0` = OS ephemeral) and start accepting concurrent peers.
         *
         * `allowed_peer_public_keys` seeds the pre-sign allowlist (each entry must be 32 bytes;
         * an empty list starts in deny-all mode until [`Self::add_allowed_peer`] is called).
         */
        @Throws(WanFfiException::class)
        public actual fun `start`(`port`: kotlin.UShort, `identitySeed`: kotlin.ByteArray, `allowedPeerPublicKeys`: List<kotlin.ByteArray>, `listener`: HubEventListener): SecureHub {
            return FfiConverterTypeSecureHub.lift(uniffiRustCallWithError(WanFfiExceptionErrorHandler) { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_constructor_securehub_start(
                    FfiConverterUShort.lower(`port`),
                    FfiConverterByteArray.lower(`identitySeed`),
                    FfiConverterSequenceByteArray.lower(`allowedPeerPublicKeys`),
                    FfiConverterTypeHubEventListener.lower(`listener`),
                    uniffiRustCallStatus,
                )
            }!!)
        }

        
    }
    
}





public object FfiConverterTypeSecureHub: FfiConverter<SecureHub, Pointer> {

    override fun lower(value: SecureHub): Pointer {
        return value.uniffiClonePointer()
    }

    override fun lift(value: Pointer): SecureHub {
        return SecureHub(value)
    }

    override fun read(buf: ByteBuffer): SecureHub {
        // The Rust code always writes pointers as 8 bytes, and will
        // fail to compile if they don't fit.
        return lift(buf.getLong().toPointer())
    }

    override fun allocationSize(value: SecureHub): ULong = 8UL

    override fun write(value: SecureHub, buf: ByteBuffer) {
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
    /**
     * Create a channel bound to a 32-byte Ed25519 identity seed.
     */
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
     * Take ownership of an established [`WanChannel`] and drive its
     * authenticated [`luciola::link::secure::SecureStream`] through this
     * session's existing `send` / `on_message` / `stats` / `disconnect` surface.
     *
     * Stops any prior LAN link and pauses the LAN dual-port tunnel (`TunnelLink`).
     * WAN sessions do not auto-reconnect (see `docs/DECISIONS.md`); on drop,
     * `on_state("closed", None)` is emitted and the caller decides whether to redial.
     */
    @Throws(WanFfiException::class)
    public actual override fun `attachWanChannel`(`channel`: WanChannel, `listener`: SecureSessionListener) {
        callWithPointer {
            uniffiRustCallWithError(WanFfiExceptionErrorHandler) { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_securesession_attach_wan_channel(
                    it,
                    FfiConverterTypeWanChannel.lower(`channel`),
                    FfiConverterTypeSecureSessionListener.lower(`listener`),
                    uniffiRustCallStatus,
                )
            }
        }
    }

    /**
     * 只断**当前这条连接**（Listen 角色的 accept 循环继续接下一个；Dial+auto 重拨）。
     *
     * 与 [`Self::disconnect`] 的语义差异是故意的也是关键的：入站会话清理（陌生连接
     * 超时、拒绝配对、等批准超时）必须用这里 —— 用 [`Self::disconnect`] 会把监听
     * 端口一起拆掉，宿主从此 TCP 连不上（真机实测过，见字段注释）。
     */
    public actual override fun `closeCurrentChannel`() {
        callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_securesession_closecurrentchannel(
                    it,
                    uniffiRustCallStatus,
                )
            }
        }
    }

    /**
     * Race-dial every candidate address (Happy Eyeballs) and run the
     * authenticated handshake on the winning socket, with a PINNED peer key.
     *
     * With `auto_reconnect` the session re-dials with exponential backoff
     * (1s..30s) whenever the channel drops, until `disconnect()`.
     */
    public actual override fun `connect`(`addresses`: List<kotlin.String>, `port`: kotlin.UShort, `pinnedPeerPublicKey`: kotlin.ByteArray?, `autoReconnect`: kotlin.Boolean, `listener`: SecureSessionListener) {
        callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_securesession_connect(
                    it,
                    FfiConverterSequenceString.lower(`addresses`),
                    FfiConverterUShort.lower(`port`),
                    FfiConverterOptionalByteArray.lower(`pinnedPeerPublicKey`),
                    FfiConverterBoolean.lower(`autoReconnect`),
                    FfiConverterTypeSecureSessionListener.lower(`listener`),
                    uniffiRustCallStatus,
                )
            }
        }
    }

    /**
     * 关闭转发端点（幂等）。
     */
    public actual override fun `disableForwardEndpoint`(): kotlin.Boolean {
        return FfiConverterBoolean.lift(callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_securesession_disable_forward_endpoint(
                    it,
                    uniffiRustCallStatus,
                )
            }
        })
    }

    /**
     * 关闭 remote endpoint（幂等）。
     */
    public actual override fun `disableRemoteEndpoint`(): kotlin.Boolean {
        return FfiConverterBoolean.lift(callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_securesession_disable_remote_endpoint(
                    it,
                    uniffiRustCallStatus,
                )
            }
        })
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

    /**
     * 启用/替换服务端转发端点（仅 listen()/Responder 角色）：规则非空、
     * `port_from <= port_to`、tunnel_port 双栈冲突探测；规则主机为 IP 字面量
     * 或主机名；`udp=true` 的规则同时放行 DOPEN（UDP 拨号）。失败同上走 on_state。
     */
    public actual override fun `enableForwardEndpoint`(`rules`: List<ForwardRuleDto>): kotlin.Boolean {
        return FfiConverterBoolean.lift(callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_securesession_enable_forward_endpoint(
                    it,
                    FfiConverterSequenceTypeForwardRuleDto.lower(`rules`),
                    uniffiRustCallStatus,
                )
            }
        })
    }

    /**
     * 启用/替换 remote endpoint ACL（v2；仅 connect()/Dial 角色）：放行
     * Responder 发起的通道并拨本机目标。规则同 enable_forward_endpoint；
     * 未启用 = 默认拒绝一切 remote forward 拨入。
     */
    public actual override fun `enableRemoteEndpoint`(`rules`: List<ForwardRuleDto>): kotlin.Boolean {
        return FfiConverterBoolean.lift(callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_securesession_enable_remote_endpoint(
                    it,
                    FfiConverterSequenceTypeForwardRuleDto.lower(`rules`),
                    uniffiRustCallStatus,
                )
            }
        })
    }

    /**
     * 快照全部转发状态：active（隧道已建立且 Guard 存活）、实际监听端口、
     * 历史折叠计数、类别（local / udp_local / remote_endpoint / endpoint / remote）。
     * 注册过任何转发/端点后即有行，重建期间 active=false。
     */
    public actual override fun `forwardStats`(): List<ForwardStatusDto> {
        return FfiConverterSequenceTypeForwardStatusDto.lift(callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_securesession_forward_stats(
                    it,
                    uniffiRustCallStatus,
                )
            }
        })
    }

    /**
     * Whether the channel currently holds an authenticated connection.
     */
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
     * 对端的 Ed25519 身份公钥（最近一次连接的）。发起侧 TOFU 时这把 key 是
     * **学来的**：调用方必须在首次连接后取走并钉存，否则重连走不了 pinned 模式。
     */
    public actual override fun `peerPublicKey`(): kotlin.ByteArray? {
        return FfiConverterOptionalByteArray.lift(callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_securesession_peerpublickey(
                    it,
                    uniffiRustCallStatus,
                )
            }
        })
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
     * 隧道 mux keepalive（v2）：`interval_ms=0` 关闭；dead_after_ms 会被
     * clamp 到 ≥ interval_ms。仅对证明过 v2 的对端执行判死（v1 对端永不误杀）。
     * 改动随下一次隧道链路重建生效。
     */
    public actual override fun `setTunnelKeepalive`(`intervalMs`: kotlin.ULong, `deadAfterMs`: kotlin.ULong) {
        callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_securesession_set_tunnel_keepalive(
                    it,
                    FfiConverterULong.lower(`intervalMs`),
                    FfiConverterULong.lower(`deadAfterMs`),
                    uniffiRustCallStatus,
                )
            }
        }
    }

    /**
     * 覆盖隧道端口（默认 = secure 端口 + 1；0 = 恢复默认）。改动触发链路重建。
     */
    public actual override fun `setTunnelPort`(`port`: kotlin.UShort): kotlin.Boolean {
        return FfiConverterBoolean.lift(callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_securesession_set_tunnel_port(
                    it,
                    FfiConverterUShort.lower(`port`),
                    uniffiRustCallStatus,
                )
            }
        })
    }

    /**
     * 注册本地监听端口，经隧道转发到对端 `host:port`（仅 connect()/Dial 角色）。
     * `host` 为 IP 字面量或主机名（v2：主机名由对端解析并按会话钉扎）。
     * `listen_port=0` → 系统分配，实端口见 [`Self::forward_stats`]。
     * 同步完成目标校验与端口冲突探测：失败返回 false 并 on_state(
     * "error", "forward_bind_failed: …" / 校验信息)。懒建立：首个注册后才建隧道。
     */
    public actual override fun `startLocalForward`(`listenPort`: kotlin.UShort, `host`: kotlin.String, `port`: kotlin.UShort): kotlin.Boolean {
        return FfiConverterBoolean.lift(callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_securesession_start_local_forward(
                    it,
                    FfiConverterUShort.lower(`listenPort`),
                    FfiConverterString.lower(`host`),
                    FfiConverterUShort.lower(`port`),
                    uniffiRustCallStatus,
                )
            }
        })
    }

    /**
     * 注册 remote forward（v2 `-R`；仅 listen()/Responder 角色）：本机
     * 127.0.0.1:listen_port 的每条入站连接经隧道（偶数通道）转发到**对端机**
     * 上的 host:port。对端须 enable_remote_endpoint 放行该目标；对端为 v1 时
     * 通道建立失败（对端 mux 按违规终止，勿对旧版本启用）。
     */
    public actual override fun `startRemoteForward`(`listenPort`: kotlin.UShort, `host`: kotlin.String, `port`: kotlin.UShort): kotlin.Boolean {
        return FfiConverterBoolean.lift(callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_securesession_start_remote_forward(
                    it,
                    FfiConverterUShort.lower(`listenPort`),
                    FfiConverterString.lower(`host`),
                    FfiConverterUShort.lower(`port`),
                    uniffiRustCallStatus,
                )
            }
        })
    }

    /**
     * 注册 UDP 转发（v2 NAT 式会话映射；仅 connect()/Dial 角色）：
     * 本机 127.0.0.1:listen_port 的每个源地址映射一条数据报通道到对端
     * host:port；对端 endpoint 的 ACL 规则须 `udp=true` 放行。
     * 映射空闲超时自动回收（默认 60s）。
     */
    public actual override fun `startUdpForward`(`listenPort`: kotlin.UShort, `host`: kotlin.String, `port`: kotlin.UShort): kotlin.Boolean {
        return FfiConverterBoolean.lift(callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_securesession_start_udp_forward(
                    it,
                    FfiConverterUShort.lower(`listenPort`),
                    FfiConverterString.lower(`host`),
                    FfiConverterUShort.lower(`port`),
                    uniffiRustCallStatus,
                )
            }
        })
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

    /**
     * 注销本地转发（停止 Guard + 折叠计数）。未注册返回 false。
     */
    public actual override fun `stopLocalForward`(`listenPort`: kotlin.UShort): kotlin.Boolean {
        return FfiConverterBoolean.lift(callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_securesession_stop_local_forward(
                    it,
                    FfiConverterUShort.lower(`listenPort`),
                    uniffiRustCallStatus,
                )
            }
        })
    }

    /**
     * 注销 remote forward。未注册返回 false。
     */
    public actual override fun `stopRemoteForward`(`listenPort`: kotlin.UShort): kotlin.Boolean {
        return FfiConverterBoolean.lift(callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_securesession_stop_remote_forward(
                    it,
                    FfiConverterUShort.lower(`listenPort`),
                    uniffiRustCallStatus,
                )
            }
        })
    }

    /**
     * 注销 UDP 转发。未注册返回 false。
     */
    public actual override fun `stopUdpForward`(`listenPort`: kotlin.UShort): kotlin.Boolean {
        return FfiConverterBoolean.lift(callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_securesession_stop_udp_forward(
                    it,
                    FfiConverterUShort.lower(`listenPort`),
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
 * Cooperative cancellation handle shared with any `transfer_*` call.
 */
public actual open class TransferCancelHandle: Disposable, TransferCancelHandleInterface {

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
     * Create a fresh non-cancelled handle.
     */
    public actual constructor() : this(
        uniffiRustCall { uniffiRustCallStatus ->
            UniffiLib.uniffi_luciola_uniffi_fn_constructor_transfercancelhandle_new(
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
                    UniffiLib.uniffi_luciola_uniffi_fn_free_transfercancelhandle(ptr, status)
                }
            }
        }
    }

    public fun uniffiClonePointer(): Pointer {
        return uniffiRustCall { status ->
            UniffiLib.uniffi_luciola_uniffi_fn_clone_transfercancelhandle(pointer!!, status)
        }!!
    }

    
    /**
     * Signal cancellation to any transfer observing this handle.
     */
    public actual override fun `cancel`() {
        callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_transfercancelhandle_cancel(
                    it,
                    uniffiRustCallStatus,
                )
            }
        }
    }

    /**
     * Whether [`Self::cancel`] has been called.
     */
    public actual override fun `isCancelled`(): kotlin.Boolean {
        return FfiConverterBoolean.lift(callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_transfercancelhandle_is_cancelled(
                    it,
                    uniffiRustCallStatus,
                )
            }
        })
    }


    
    
    public actual companion object
    
}





public object FfiConverterTypeTransferCancelHandle: FfiConverter<TransferCancelHandle, Pointer> {

    override fun lower(value: TransferCancelHandle): Pointer {
        return value.uniffiClonePointer()
    }

    override fun lift(value: Pointer): TransferCancelHandle {
        return TransferCancelHandle(value)
    }

    override fun read(buf: ByteBuffer): TransferCancelHandle {
        // The Rust code always writes pointers as 8 bytes, and will
        // fail to compile if they don't fit.
        return lift(buf.getLong().toPointer())
    }

    override fun allocationSize(value: TransferCancelHandle): ULong = 8UL

    override fun write(value: TransferCancelHandle, buf: ByteBuffer) {
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
    /**
     * Restore a trust store from its JSON form, or start empty.
     */
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

    
    /**
     * Every paired device, in insertion order.
     */
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



/**
 * An established WAN channel.
 *
 * `connect_wan` blocks the calling thread while it exchanges candidates,
 * punches and runs the authenticated handshake, bounded by
 * `punch_timeout_ms` and the signalling timeout. On mobile platforms call it
 * from a worker thread, never from the UI thread.
 */
public actual open class WanChannel: Disposable, WanChannelInterface {

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
                    UniffiLib.uniffi_luciola_uniffi_fn_free_wanchannel(ptr, status)
                }
            }
        }
    }

    public fun uniffiClonePointer(): Pointer {
        return uniffiRustCall { status ->
            UniffiLib.uniffi_luciola_uniffi_fn_clone_wanchannel(pointer!!, status)
        }!!
    }

    
    /**
     * The data plane this channel actually uses.
     *
     * Returns `Unknown` after [`WanChannel::shutdown`] or when the engine
     * reports a code this build does not know.
     */
    public actual override fun `channelType`(): WanChannelKind {
        return FfiConverterTypeWanChannelKind.lift(callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_wanchannel_channel_type(
                    it,
                    uniffiRustCallStatus,
                )
            }
        })
    }

    /**
     * The peer's socket endpoint, when the transport exposes one.
     */
    public actual override fun `remoteAddr`(): kotlin.String? {
        return FfiConverterOptionalString.lift(callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_wanchannel_remote_addr(
                    it,
                    uniffiRustCallStatus,
                )
            }
        })
    }

    /**
     * Close the channel. Idempotent; a second call is a no-op.
     */
    @Throws(WanFfiException::class)
    public actual override fun `shutdown`() {
        callWithPointer {
            uniffiRustCallWithError(WanFfiExceptionErrorHandler) { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_wanchannel_shutdown(
                    it,
                    uniffiRustCallStatus,
                )
            }
        }
    }


    
    
    public actual companion object
    
}





public object FfiConverterTypeWanChannel: FfiConverter<WanChannel, Pointer> {

    override fun lower(value: WanChannel): Pointer {
        return value.uniffiClonePointer()
    }

    override fun lift(value: Pointer): WanChannel {
        return WanChannel(value)
    }

    override fun read(buf: ByteBuffer): WanChannel {
        // The Rust code always writes pointers as 8 bytes, and will
        // fail to compile if they don't fit.
        return lift(buf.getLong().toPointer())
    }

    override fun allocationSize(value: WanChannel): ULong = 8UL

    override fun write(value: WanChannel, buf: ByteBuffer) {
        // The Rust code always expects pointers written as 8 bytes,
        // and will fail to compile if they don't fit.
        buf.putLong(lower(value).toLong())
    }
}



/**
 * Multiplexed TCP/UDP port-forwarding session running over one [`WanChannel`].
 * Does not alter the LAN dual-port `SecureSession` tunnel contract.
 */
public actual open class WanTunnelSession: Disposable, WanTunnelSessionInterface {

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
                    UniffiLib.uniffi_luciola_uniffi_fn_free_wantunnelsession(ptr, status)
                }
            }
        }
    }

    public fun uniffiClonePointer(): Pointer {
        return uniffiRustCall { status ->
            UniffiLib.uniffi_luciola_uniffi_fn_clone_wantunnelsession(pointer!!, status)
        }!!
    }

    
    /**
     * Transport plane of the underlying channel.
     */
    public actual override fun `channelType`(): WanChannelKind {
        return FfiConverterTypeWanChannelKind.lift(callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_wantunnelsession_channel_type(
                    it,
                    uniffiRustCallStatus,
                )
            }
        })
    }

    /**
     * Disable the inbound ACL forward endpoint.
     */
    public actual override fun `disableForwardEndpoint`() {
        callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_wantunnelsession_disable_forward_endpoint(
                    it,
                    uniffiRustCallStatus,
                )
            }
        }
    }

    /**
     * Enable or replace the inbound ACL forward endpoint (`--allow`).
     */
    @Throws(WanFfiException::class)
    public actual override fun `enableForwardEndpoint`(`rules`: List<ForwardRuleDto>) {
        callWithPointer {
            uniffiRustCallWithError(WanFfiExceptionErrorHandler) { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_wantunnelsession_enable_forward_endpoint(
                    it,
                    FfiConverterSequenceTypeForwardRuleDto.lower(`rules`),
                    uniffiRustCallStatus,
                )
            }
        }
    }

    /**
     * Whether the underlying mux session is still alive.
     */
    public actual override fun `isAlive`(): kotlin.Boolean {
        return FfiConverterBoolean.lift(callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_wantunnelsession_is_alive(
                    it,
                    uniffiRustCallStatus,
                )
            }
        })
    }

    /**
     * Stop all forwards and shut down the tunnel. Idempotent.
     */
    public actual override fun `shutdown`() {
        callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_wantunnelsession_shutdown(
                    it,
                    uniffiRustCallStatus,
                )
            }
        }
    }

    /**
     * Start a local TCP forward (`127.0.0.1:listen_port` → peer `host:port`).
     * Returns the actual bound local port (helpful when `listen_port == 0`).
     */
    @Throws(WanFfiException::class)
    public actual override fun `startLocalForward`(`listenPort`: kotlin.UShort, `host`: kotlin.String, `port`: kotlin.UShort): kotlin.UShort {
        return FfiConverterUShort.lift(callWithPointer {
            uniffiRustCallWithError(WanFfiExceptionErrorHandler) { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_wantunnelsession_start_local_forward(
                    it,
                    FfiConverterUShort.lower(`listenPort`),
                    FfiConverterString.lower(`host`),
                    FfiConverterUShort.lower(`port`),
                    uniffiRustCallStatus,
                )
            }
        })
    }

    /**
     * Start a local UDP forward (`127.0.0.1:listen_port` → peer `host:port`).
     */
    @Throws(WanFfiException::class)
    public actual override fun `startUdpForward`(`listenPort`: kotlin.UShort, `host`: kotlin.String, `port`: kotlin.UShort): kotlin.UShort {
        return FfiConverterUShort.lift(callWithPointer {
            uniffiRustCallWithError(WanFfiExceptionErrorHandler) { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_wantunnelsession_start_udp_forward(
                    it,
                    FfiConverterUShort.lower(`listenPort`),
                    FfiConverterString.lower(`host`),
                    FfiConverterUShort.lower(`port`),
                    uniffiRustCallStatus,
                )
            }
        })
    }

    /**
     * Snapshot active forward stats.
     */
    public actual override fun `stats`(): List<ForwardStatusDto> {
        return FfiConverterSequenceTypeForwardStatusDto.lift(callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_wantunnelsession_stats(
                    it,
                    uniffiRustCallStatus,
                )
            }
        })
    }

    /**
     * Stop a local TCP forward on `listen_port`.
     */
    public actual override fun `stopLocalForward`(`listenPort`: kotlin.UShort): kotlin.Boolean {
        return FfiConverterBoolean.lift(callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_wantunnelsession_stop_local_forward(
                    it,
                    FfiConverterUShort.lower(`listenPort`),
                    uniffiRustCallStatus,
                )
            }
        })
    }

    /**
     * Stop a local UDP forward on `listen_port`.
     */
    public actual override fun `stopUdpForward`(`listenPort`: kotlin.UShort): kotlin.Boolean {
        return FfiConverterBoolean.lift(callWithPointer {
            uniffiRustCall { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_method_wantunnelsession_stop_udp_forward(
                    it,
                    FfiConverterUShort.lower(`listenPort`),
                    uniffiRustCallStatus,
                )
            }
        })
    }


    
    public actual companion object {
        
        /**
         * Consume `channel` and start a [`luciola_tunnel::DirectTunnelSession`] on `wan_runtime()`.
         */
        @Throws(WanFfiException::class)
        public actual fun `fromWanChannel`(`channel`: WanChannel, `isInitiator`: kotlin.Boolean): WanTunnelSession {
            return FfiConverterTypeWanTunnelSession.lift(uniffiRustCallWithError(WanFfiExceptionErrorHandler) { uniffiRustCallStatus ->
                UniffiLib.uniffi_luciola_uniffi_fn_constructor_wantunnelsession_from_wan_channel(
                    FfiConverterTypeWanChannel.lower(`channel`),
                    FfiConverterBoolean.lower(`isInitiator`),
                    uniffiRustCallStatus,
                )
            }!!)
        }

        
    }
    
}





public object FfiConverterTypeWanTunnelSession: FfiConverter<WanTunnelSession, Pointer> {

    override fun lower(value: WanTunnelSession): Pointer {
        return value.uniffiClonePointer()
    }

    override fun lift(value: Pointer): WanTunnelSession {
        return WanTunnelSession(value)
    }

    override fun read(buf: ByteBuffer): WanTunnelSession {
        // The Rust code always writes pointers as 8 bytes, and will
        // fail to compile if they don't fit.
        return lift(buf.getLong().toPointer())
    }

    override fun allocationSize(value: WanTunnelSession): ULong = 8UL

    override fun write(value: WanTunnelSession, buf: ByteBuffer) {
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




public object FfiConverterTypeErrorInfoDto: FfiConverterRustBuffer<ErrorInfoDto> {
    override fun read(buf: ByteBuffer): ErrorInfoDto {
        return ErrorInfoDto(
            FfiConverterString.read(buf),
            FfiConverterString.read(buf),
            FfiConverterBoolean.read(buf),
        )
    }

    override fun allocationSize(value: ErrorInfoDto): ULong = (
            FfiConverterString.allocationSize(value.`code`) +
            FfiConverterString.allocationSize(value.`message`) +
            FfiConverterBoolean.allocationSize(value.`retryable`)
    )

    override fun write(value: ErrorInfoDto, buf: ByteBuffer) {
        FfiConverterString.write(value.`code`, buf)
        FfiConverterString.write(value.`message`, buf)
        FfiConverterBoolean.write(value.`retryable`, buf)
    }
}




public object FfiConverterTypeForwardRuleDto: FfiConverterRustBuffer<ForwardRuleDto> {
    override fun read(buf: ByteBuffer): ForwardRuleDto {
        return ForwardRuleDto(
            FfiConverterString.read(buf),
            FfiConverterUShort.read(buf),
            FfiConverterUShort.read(buf),
            FfiConverterBoolean.read(buf),
        )
    }

    override fun allocationSize(value: ForwardRuleDto): ULong = (
            FfiConverterString.allocationSize(value.`host`) +
            FfiConverterUShort.allocationSize(value.`portFrom`) +
            FfiConverterUShort.allocationSize(value.`portTo`) +
            FfiConverterBoolean.allocationSize(value.`udp`)
    )

    override fun write(value: ForwardRuleDto, buf: ByteBuffer) {
        FfiConverterString.write(value.`host`, buf)
        FfiConverterUShort.write(value.`portFrom`, buf)
        FfiConverterUShort.write(value.`portTo`, buf)
        FfiConverterBoolean.write(value.`udp`, buf)
    }
}




public object FfiConverterTypeForwardStatusDto: FfiConverterRustBuffer<ForwardStatusDto> {
    override fun read(buf: ByteBuffer): ForwardStatusDto {
        return ForwardStatusDto(
            FfiConverterBoolean.read(buf),
            FfiConverterUShort.read(buf),
            FfiConverterULong.read(buf),
            FfiConverterULong.read(buf),
            FfiConverterULong.read(buf),
            FfiConverterULong.read(buf),
            FfiConverterString.read(buf),
        )
    }

    override fun allocationSize(value: ForwardStatusDto): ULong = (
            FfiConverterBoolean.allocationSize(value.`active`) +
            FfiConverterUShort.allocationSize(value.`listenPort`) +
            FfiConverterULong.allocationSize(value.`channelsOpen`) +
            FfiConverterULong.allocationSize(value.`channelsTotal`) +
            FfiConverterULong.allocationSize(value.`dialDenied`) +
            FfiConverterULong.allocationSize(value.`dialFailed`) +
            FfiConverterString.allocationSize(value.`kind`)
    )

    override fun write(value: ForwardStatusDto, buf: ByteBuffer) {
        FfiConverterBoolean.write(value.`active`, buf)
        FfiConverterUShort.write(value.`listenPort`, buf)
        FfiConverterULong.write(value.`channelsOpen`, buf)
        FfiConverterULong.write(value.`channelsTotal`, buf)
        FfiConverterULong.write(value.`dialDenied`, buf)
        FfiConverterULong.write(value.`dialFailed`, buf)
        FfiConverterString.write(value.`kind`, buf)
    }
}




public object FfiConverterTypeHubPeerInfoDto: FfiConverterRustBuffer<HubPeerInfoDto> {
    override fun read(buf: ByteBuffer): HubPeerInfoDto {
        return HubPeerInfoDto(
            FfiConverterString.read(buf),
            FfiConverterByteArray.read(buf),
            FfiConverterString.read(buf),
        )
    }

    override fun allocationSize(value: HubPeerInfoDto): ULong = (
            FfiConverterString.allocationSize(value.`fingerprint`) +
            FfiConverterByteArray.allocationSize(value.`publicKey`) +
            FfiConverterString.allocationSize(value.`remoteAddr`)
    )

    override fun write(value: HubPeerInfoDto, buf: ByteBuffer) {
        FfiConverterString.write(value.`fingerprint`, buf)
        FfiConverterByteArray.write(value.`publicKey`, buf)
        FfiConverterString.write(value.`remoteAddr`, buf)
    }
}




public object FfiConverterTypeLanDialConfigDto: FfiConverterRustBuffer<LanDialConfigDto> {
    override fun read(buf: ByteBuffer): LanDialConfigDto {
        return LanDialConfigDto(
            FfiConverterSequenceString.read(buf),
            FfiConverterUShort.read(buf),
            FfiConverterByteArray.read(buf),
            FfiConverterByteArray.read(buf),
        )
    }

    override fun allocationSize(value: LanDialConfigDto): ULong = (
            FfiConverterSequenceString.allocationSize(value.`addresses`) +
            FfiConverterUShort.allocationSize(value.`port`) +
            FfiConverterByteArray.allocationSize(value.`identitySeed`) +
            FfiConverterByteArray.allocationSize(value.`peerPublicKey`)
    )

    override fun write(value: LanDialConfigDto, buf: ByteBuffer) {
        FfiConverterSequenceString.write(value.`addresses`, buf)
        FfiConverterUShort.write(value.`port`, buf)
        FfiConverterByteArray.write(value.`identitySeed`, buf)
        FfiConverterByteArray.write(value.`peerPublicKey`, buf)
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
            FfiConverterOptionalString.allocationSize(value.`pin`) +
            FfiConverterOptionalString.allocationSize(value.`psk`)
    )

    override fun write(value: PairingInfo, buf: ByteBuffer) {
        FfiConverterString.write(value.`name`, buf)
        FfiConverterOptionalString.write(value.`product`, buf)
        FfiConverterUShort.write(value.`port`, buf)
        FfiConverterSequenceString.write(value.`addrs`, buf)
        FfiConverterOptionalString.write(value.`fingerprint`, buf)
        FfiConverterOptionalString.write(value.`publicKey`, buf)
        FfiConverterOptionalString.write(value.`pin`, buf)
        FfiConverterOptionalString.write(value.`psk`, buf)
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




public object FfiConverterTypeRelayEphemeralKeyPair: FfiConverterRustBuffer<RelayEphemeralKeyPair> {
    override fun read(buf: ByteBuffer): RelayEphemeralKeyPair {
        return RelayEphemeralKeyPair(
            FfiConverterByteArray.read(buf),
            FfiConverterByteArray.read(buf),
        )
    }

    override fun allocationSize(value: RelayEphemeralKeyPair): ULong = (
            FfiConverterByteArray.allocationSize(value.`secret`) +
            FfiConverterByteArray.allocationSize(value.`public_`)
    )

    override fun write(value: RelayEphemeralKeyPair, buf: ByteBuffer) {
        FfiConverterByteArray.write(value.`secret`, buf)
        FfiConverterByteArray.write(value.`public_`, buf)
    }
}




public object FfiConverterTypeRelaySessionKeys: FfiConverterRustBuffer<RelaySessionKeys> {
    override fun read(buf: ByteBuffer): RelaySessionKeys {
        return RelaySessionKeys(
            FfiConverterByteArray.read(buf),
            FfiConverterByteArray.read(buf),
        )
    }

    override fun allocationSize(value: RelaySessionKeys): ULong = (
            FfiConverterByteArray.allocationSize(value.`sendKey`) +
            FfiConverterByteArray.allocationSize(value.`recvKey`)
    )

    override fun write(value: RelaySessionKeys, buf: ByteBuffer) {
        FfiConverterByteArray.write(value.`sendKey`, buf)
        FfiConverterByteArray.write(value.`recvKey`, buf)
    }
}




public object FfiConverterTypeTransferProgressDto: FfiConverterRustBuffer<TransferProgressDto> {
    override fun read(buf: ByteBuffer): TransferProgressDto {
        return TransferProgressDto(
            FfiConverterString.read(buf),
            FfiConverterULong.read(buf),
            FfiConverterULong.read(buf),
            FfiConverterTypeWanChannelKind.read(buf),
            FfiConverterBoolean.read(buf),
        )
    }

    override fun allocationSize(value: TransferProgressDto): ULong = (
            FfiConverterString.allocationSize(value.`transferId`) +
            FfiConverterULong.allocationSize(value.`bytesDone`) +
            FfiConverterULong.allocationSize(value.`totalBytes`) +
            FfiConverterTypeWanChannelKind.allocationSize(value.`channelType`) +
            FfiConverterBoolean.allocationSize(value.`resumed`)
    )

    override fun write(value: TransferProgressDto, buf: ByteBuffer) {
        FfiConverterString.write(value.`transferId`, buf)
        FfiConverterULong.write(value.`bytesDone`, buf)
        FfiConverterULong.write(value.`totalBytes`, buf)
        FfiConverterTypeWanChannelKind.write(value.`channelType`, buf)
        FfiConverterBoolean.write(value.`resumed`, buf)
    }
}




public object FfiConverterTypeTransferReceiptDto: FfiConverterRustBuffer<TransferReceiptDto> {
    override fun read(buf: ByteBuffer): TransferReceiptDto {
        return TransferReceiptDto(
            FfiConverterString.read(buf),
            FfiConverterString.read(buf),
            FfiConverterULong.read(buf),
            FfiConverterString.read(buf),
            FfiConverterOptionalString.read(buf),
            FfiConverterTypeWanChannelKind.read(buf),
        )
    }

    override fun allocationSize(value: TransferReceiptDto): ULong = (
            FfiConverterString.allocationSize(value.`transferId`) +
            FfiConverterString.allocationSize(value.`fileName`) +
            FfiConverterULong.allocationSize(value.`totalBytes`) +
            FfiConverterString.allocationSize(value.`sha256Hex`) +
            FfiConverterOptionalString.allocationSize(value.`savedPath`) +
            FfiConverterTypeWanChannelKind.allocationSize(value.`channelType`)
    )

    override fun write(value: TransferReceiptDto, buf: ByteBuffer) {
        FfiConverterString.write(value.`transferId`, buf)
        FfiConverterString.write(value.`fileName`, buf)
        FfiConverterULong.write(value.`totalBytes`, buf)
        FfiConverterString.write(value.`sha256Hex`, buf)
        FfiConverterOptionalString.write(value.`savedPath`, buf)
        FfiConverterTypeWanChannelKind.write(value.`channelType`, buf)
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




public object FfiConverterTypeWanConfig: FfiConverterRustBuffer<WanConfig> {
    override fun read(buf: ByteBuffer): WanConfig {
        return WanConfig(
            FfiConverterString.read(buf),
            FfiConverterString.read(buf),
            FfiConverterULong.read(buf),
            FfiConverterByteArray.read(buf),
            FfiConverterByteArray.read(buf),
            FfiConverterByteArray.read(buf),
            FfiConverterByteArray.read(buf),
            FfiConverterTypeWanRelayConfig.read(buf),
            FfiConverterOptionalString.read(buf),
            FfiConverterULong.read(buf),
            FfiConverterBoolean.read(buf),
            FfiConverterUShort.read(buf),
            FfiConverterBoolean.read(buf),
        )
    }

    override fun allocationSize(value: WanConfig): ULong = (
            FfiConverterString.allocationSize(value.`signalingEndpoint`) +
            FfiConverterString.allocationSize(value.`room`) +
            FfiConverterULong.allocationSize(value.`epoch`) +
            FfiConverterByteArray.allocationSize(value.`psk`) +
            FfiConverterByteArray.allocationSize(value.`identitySeed`) +
            FfiConverterByteArray.allocationSize(value.`myPublicKey`) +
            FfiConverterByteArray.allocationSize(value.`peerPublicKey`) +
            FfiConverterTypeWanRelayConfig.allocationSize(value.`relay`) +
            FfiConverterOptionalString.allocationSize(value.`stunServer`) +
            FfiConverterULong.allocationSize(value.`punchTimeoutMs`) +
            FfiConverterBoolean.allocationSize(value.`enableHolePunching`) +
            FfiConverterUShort.allocationSize(value.`tcpPort`) +
            FfiConverterBoolean.allocationSize(value.`progressive`)
    )

    override fun write(value: WanConfig, buf: ByteBuffer) {
        FfiConverterString.write(value.`signalingEndpoint`, buf)
        FfiConverterString.write(value.`room`, buf)
        FfiConverterULong.write(value.`epoch`, buf)
        FfiConverterByteArray.write(value.`psk`, buf)
        FfiConverterByteArray.write(value.`identitySeed`, buf)
        FfiConverterByteArray.write(value.`myPublicKey`, buf)
        FfiConverterByteArray.write(value.`peerPublicKey`, buf)
        FfiConverterTypeWanRelayConfig.write(value.`relay`, buf)
        FfiConverterOptionalString.write(value.`stunServer`, buf)
        FfiConverterULong.write(value.`punchTimeoutMs`, buf)
        FfiConverterBoolean.write(value.`enableHolePunching`, buf)
        FfiConverterUShort.write(value.`tcpPort`, buf)
        FfiConverterBoolean.write(value.`progressive`, buf)
    }
}




public object FfiConverterTypeWanRelayConfig: FfiConverterRustBuffer<WanRelayConfig> {
    override fun read(buf: ByteBuffer): WanRelayConfig {
        return WanRelayConfig(
            FfiConverterBoolean.read(buf),
            FfiConverterBoolean.read(buf),
            FfiConverterSequenceString.read(buf),
            FfiConverterULong.read(buf),
        )
    }

    override fun allocationSize(value: WanRelayConfig): ULong = (
            FfiConverterBoolean.allocationSize(value.`allowRelay`) +
            FfiConverterBoolean.allocationSize(value.`allowWanSignaling`) +
            FfiConverterSequenceString.allocationSize(value.`relayEndpoints`) +
            FfiConverterULong.allocationSize(value.`connectionTimeoutMs`)
    )

    override fun write(value: WanRelayConfig, buf: ByteBuffer) {
        FfiConverterBoolean.write(value.`allowRelay`, buf)
        FfiConverterBoolean.write(value.`allowWanSignaling`, buf)
        FfiConverterSequenceString.write(value.`relayEndpoints`, buf)
        FfiConverterULong.write(value.`connectionTimeoutMs`, buf)
    }
}





public object FfiConverterTypeChannelType: FfiConverterRustBuffer<ChannelType> {
    override fun read(buf: ByteBuffer): ChannelType = try {
        ChannelType.values()[buf.getInt() - 1]
    } catch (e: IndexOutOfBoundsException) {
        throw RuntimeException("invalid enum value, something is very wrong!!", e)
    }

    override fun allocationSize(value: ChannelType): ULong = 4UL

    override fun write(value: ChannelType, buf: ByteBuffer) {
        buf.putInt(value.ordinal + 1)
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




public object RelayCryptoExceptionErrorHandler : UniffiRustCallStatusErrorHandler<RelayCryptoException> {
    override fun lift(errorBuf: RustBufferByValue): RelayCryptoException = FfiConverterTypeRelayCryptoError.lift(errorBuf)
}

public object FfiConverterTypeRelayCryptoError : FfiConverterRustBuffer<RelayCryptoException> {
    override fun read(buf: ByteBuffer): RelayCryptoException {
        return when (buf.getInt()) {
            1 -> RelayCryptoException.AeadOpenFailed()
            2 -> RelayCryptoException.BadKeyLength()
            else -> throw RuntimeException("invalid error enum value, something is very wrong!!")
        }
    }

    override fun allocationSize(value: RelayCryptoException): ULong {
        return when (value) {
            is RelayCryptoException.AeadOpenFailed -> (
                // Add the size for the Int that specifies the variant plus the size needed for all fields
                4UL
            )
            is RelayCryptoException.BadKeyLength -> (
                // Add the size for the Int that specifies the variant plus the size needed for all fields
                4UL
            )
        }
    }

    override fun write(value: RelayCryptoException, buf: ByteBuffer) {
        when (value) {
            is RelayCryptoException.AeadOpenFailed -> {
                buf.putInt(1)
                Unit
            }
            is RelayCryptoException.BadKeyLength -> {
                buf.putInt(2)
                Unit
            }
        }.let { /* this makes the `when` an expression, which ensures it is exhaustive */ }
    }
}





public object FfiConverterTypeRoutePolicyKind: FfiConverterRustBuffer<RoutePolicyKind> {
    override fun read(buf: ByteBuffer): RoutePolicyKind = try {
        RoutePolicyKind.values()[buf.getInt() - 1]
    } catch (e: IndexOutOfBoundsException) {
        throw RuntimeException("invalid enum value, something is very wrong!!", e)
    }

    override fun allocationSize(value: RoutePolicyKind): ULong = 4UL

    override fun write(value: RoutePolicyKind, buf: ByteBuffer) {
        buf.putInt(value.ordinal + 1)
    }
}




public object TransferFfiExceptionErrorHandler : UniffiRustCallStatusErrorHandler<TransferFfiException> {
    override fun lift(errorBuf: RustBufferByValue): TransferFfiException = FfiConverterTypeTransferFfiError.lift(errorBuf)
}

public object FfiConverterTypeTransferFfiError : FfiConverterRustBuffer<TransferFfiException> {
    override fun read(buf: ByteBuffer): TransferFfiException {
        return when (buf.getInt()) {
            1 -> TransferFfiException.InvalidConfig(
                FfiConverterString.read(buf),
                )
            2 -> TransferFfiException.QuotaExceeded(
                FfiConverterString.read(buf),
                )
            3 -> TransferFfiException.Cancelled()
            4 -> TransferFfiException.TransferFailed(
                FfiConverterString.read(buf),
                )
            else -> throw RuntimeException("invalid error enum value, something is very wrong!!")
        }
    }

    override fun allocationSize(value: TransferFfiException): ULong {
        return when (value) {
            is TransferFfiException.InvalidConfig -> (
                // Add the size for the Int that specifies the variant plus the size needed for all fields
                4UL
                + FfiConverterString.allocationSize(value.`detail`)
            )
            is TransferFfiException.QuotaExceeded -> (
                // Add the size for the Int that specifies the variant plus the size needed for all fields
                4UL
                + FfiConverterString.allocationSize(value.`detail`)
            )
            is TransferFfiException.Cancelled -> (
                // Add the size for the Int that specifies the variant plus the size needed for all fields
                4UL
            )
            is TransferFfiException.TransferFailed -> (
                // Add the size for the Int that specifies the variant plus the size needed for all fields
                4UL
                + FfiConverterString.allocationSize(value.`detail`)
            )
        }
    }

    override fun write(value: TransferFfiException, buf: ByteBuffer) {
        when (value) {
            is TransferFfiException.InvalidConfig -> {
                buf.putInt(1)
                FfiConverterString.write(value.`detail`, buf)
                Unit
            }
            is TransferFfiException.QuotaExceeded -> {
                buf.putInt(2)
                FfiConverterString.write(value.`detail`, buf)
                Unit
            }
            is TransferFfiException.Cancelled -> {
                buf.putInt(3)
                Unit
            }
            is TransferFfiException.TransferFailed -> {
                buf.putInt(4)
                FfiConverterString.write(value.`detail`, buf)
                Unit
            }
        }.let { /* this makes the `when` an expression, which ensures it is exhaustive */ }
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





public object FfiConverterTypeWanChannelKind: FfiConverterRustBuffer<WanChannelKind> {
    override fun read(buf: ByteBuffer): WanChannelKind = try {
        WanChannelKind.values()[buf.getInt() - 1]
    } catch (e: IndexOutOfBoundsException) {
        throw RuntimeException("invalid enum value, something is very wrong!!", e)
    }

    override fun allocationSize(value: WanChannelKind): ULong = 4UL

    override fun write(value: WanChannelKind, buf: ByteBuffer) {
        buf.putInt(value.ordinal + 1)
    }
}




public object WanFfiExceptionErrorHandler : UniffiRustCallStatusErrorHandler<WanFfiException> {
    override fun lift(errorBuf: RustBufferByValue): WanFfiException = FfiConverterTypeWanFfiError.lift(errorBuf)
}

public object FfiConverterTypeWanFfiError : FfiConverterRustBuffer<WanFfiException> {
    override fun read(buf: ByteBuffer): WanFfiException {
        return when (buf.getInt()) {
            1 -> WanFfiException.PolicyDenied(
                FfiConverterString.read(buf),
                )
            2 -> WanFfiException.Io(
                FfiConverterString.read(buf),
                )
            3 -> WanFfiException.Signaling(
                FfiConverterString.read(buf),
                )
            4 -> WanFfiException.NoRoute(
                FfiConverterString.read(buf),
                )
            5 -> WanFfiException.Handshake(
                FfiConverterString.read(buf),
                )
            6 -> WanFfiException.InvalidConfig(
                FfiConverterString.read(buf),
                )
            else -> throw RuntimeException("invalid error enum value, something is very wrong!!")
        }
    }

    override fun allocationSize(value: WanFfiException): ULong {
        return when (value) {
            is WanFfiException.PolicyDenied -> (
                // Add the size for the Int that specifies the variant plus the size needed for all fields
                4UL
                + FfiConverterString.allocationSize(value.`detail`)
            )
            is WanFfiException.Io -> (
                // Add the size for the Int that specifies the variant plus the size needed for all fields
                4UL
                + FfiConverterString.allocationSize(value.`detail`)
            )
            is WanFfiException.Signaling -> (
                // Add the size for the Int that specifies the variant plus the size needed for all fields
                4UL
                + FfiConverterString.allocationSize(value.`detail`)
            )
            is WanFfiException.NoRoute -> (
                // Add the size for the Int that specifies the variant plus the size needed for all fields
                4UL
                + FfiConverterString.allocationSize(value.`detail`)
            )
            is WanFfiException.Handshake -> (
                // Add the size for the Int that specifies the variant plus the size needed for all fields
                4UL
                + FfiConverterString.allocationSize(value.`detail`)
            )
            is WanFfiException.InvalidConfig -> (
                // Add the size for the Int that specifies the variant plus the size needed for all fields
                4UL
                + FfiConverterString.allocationSize(value.`detail`)
            )
        }
    }

    override fun write(value: WanFfiException, buf: ByteBuffer) {
        when (value) {
            is WanFfiException.PolicyDenied -> {
                buf.putInt(1)
                FfiConverterString.write(value.`detail`, buf)
                Unit
            }
            is WanFfiException.Io -> {
                buf.putInt(2)
                FfiConverterString.write(value.`detail`, buf)
                Unit
            }
            is WanFfiException.Signaling -> {
                buf.putInt(3)
                FfiConverterString.write(value.`detail`, buf)
                Unit
            }
            is WanFfiException.NoRoute -> {
                buf.putInt(4)
                FfiConverterString.write(value.`detail`, buf)
                Unit
            }
            is WanFfiException.Handshake -> {
                buf.putInt(5)
                FfiConverterString.write(value.`detail`, buf)
                Unit
            }
            is WanFfiException.InvalidConfig -> {
                buf.putInt(6)
                FfiConverterString.write(value.`detail`, buf)
                Unit
            }
        }.let { /* this makes the `when` an expression, which ensures it is exhaustive */ }
    }
}






// Put the implementation in an object so we don't pollute the top-level namespace
internal object uniffiCallbackInterfaceHubEventListener {
    internal object `onPeerConnected`: UniffiCallbackInterfaceHubEventListenerMethod0 {
        override fun callback (
            `uniffiHandle`: Long,
            `peer`: RustBufferByValue,
            `uniffiOutReturn`: Pointer,
            uniffiCallStatus: UniffiRustCallStatus,
        ) {
            val uniffiObj = FfiConverterTypeHubEventListener.handleMap.get(uniffiHandle)
            val makeCall = { ->
                uniffiObj.`onPeerConnected`(
                    FfiConverterTypeHubPeerInfoDto.lift(`peer`),
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
    internal object `onMessage`: UniffiCallbackInterfaceHubEventListenerMethod1 {
        override fun callback (
            `uniffiHandle`: Long,
            `fingerprint`: RustBufferByValue,
            `remoteAddr`: RustBufferByValue,
            `payload`: RustBufferByValue,
            `uniffiOutReturn`: Pointer,
            uniffiCallStatus: UniffiRustCallStatus,
        ) {
            val uniffiObj = FfiConverterTypeHubEventListener.handleMap.get(uniffiHandle)
            val makeCall = { ->
                uniffiObj.`onMessage`(
                    FfiConverterString.lift(`fingerprint`),
                    FfiConverterString.lift(`remoteAddr`),
                    FfiConverterByteArray.lift(`payload`),
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
    internal object `onPeerDisconnected`: UniffiCallbackInterfaceHubEventListenerMethod2 {
        override fun callback (
            `uniffiHandle`: Long,
            `fingerprint`: RustBufferByValue,
            `uniffiOutReturn`: Pointer,
            uniffiCallStatus: UniffiRustCallStatus,
        ) {
            val uniffiObj = FfiConverterTypeHubEventListener.handleMap.get(uniffiHandle)
            val makeCall = { ->
                uniffiObj.`onPeerDisconnected`(
                    FfiConverterString.lift(`fingerprint`),
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
    internal object `onPeerRejected`: UniffiCallbackInterfaceHubEventListenerMethod3 {
        override fun callback (
            `uniffiHandle`: Long,
            `remoteAddr`: RustBufferByValue,
            `reason`: RustBufferByValue,
            `uniffiOutReturn`: Pointer,
            uniffiCallStatus: UniffiRustCallStatus,
        ) {
            val uniffiObj = FfiConverterTypeHubEventListener.handleMap.get(uniffiHandle)
            val makeCall = { ->
                uniffiObj.`onPeerRejected`(
                    FfiConverterString.lift(`remoteAddr`),
                    FfiConverterString.lift(`reason`),
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
            FfiConverterTypeHubEventListener.handleMap.remove(handle)
        }
    }

    internal val vtable = UniffiVTableCallbackInterfaceHubEventListener(
        `onPeerConnected`,
        `onMessage`,
        `onPeerDisconnected`,
        `onPeerRejected`,
        uniffiFree,
    )

    internal fun register(lib: UniffiLib) {
        lib.uniffi_luciola_uniffi_fn_init_callback_vtable_hubeventlistener(vtable)
    }
}

public object FfiConverterTypeHubEventListener : FfiConverterCallbackInterface<HubEventListener>()






// Put the implementation in an object so we don't pollute the top-level namespace
internal object uniffiCallbackInterfaceLogSink {
    internal object `log`: UniffiCallbackInterfaceLogSinkMethod0 {
        override fun callback (
            `uniffiHandle`: Long,
            `level`: RustBufferByValue,
            `message`: RustBufferByValue,
            `uniffiOutReturn`: Pointer,
            uniffiCallStatus: UniffiRustCallStatus,
        ) {
            val uniffiObj = FfiConverterTypeLogSink.handleMap.get(uniffiHandle)
            val makeCall = { ->
                uniffiObj.`log`(
                    FfiConverterString.lift(`level`),
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
            FfiConverterTypeLogSink.handleMap.remove(handle)
        }
    }

    internal val vtable = UniffiVTableCallbackInterfaceLogSink(
        `log`,
        uniffiFree,
    )

    internal fun register(lib: UniffiLib) {
        lib.uniffi_luciola_uniffi_fn_init_callback_vtable_logsink(vtable)
    }
}

public object FfiConverterTypeLogSink : FfiConverterCallbackInterface<LogSink>()






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
            `peerFingerprint`: RustBufferByValue,
            `remoteAddr`: RustBufferByValue,
            `uniffiOutReturn`: Pointer,
            uniffiCallStatus: UniffiRustCallStatus,
        ) {
            val uniffiObj = FfiConverterTypeSecureSessionListener.handleMap.get(uniffiHandle)
            val makeCall = { ->
                uniffiObj.`onMessage`(
                    FfiConverterByteArray.lift(`message`),
                    FfiConverterString.lift(`peerFingerprint`),
                    FfiConverterOptionalString.lift(`remoteAddr`),
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






// Put the implementation in an object so we don't pollute the top-level namespace
internal object uniffiCallbackInterfaceTransferListener {
    internal object `onProgress`: UniffiCallbackInterfaceTransferListenerMethod0 {
        override fun callback (
            `uniffiHandle`: Long,
            `progress`: RustBufferByValue,
            `uniffiOutReturn`: Pointer,
            uniffiCallStatus: UniffiRustCallStatus,
        ) {
            val uniffiObj = FfiConverterTypeTransferListener.handleMap.get(uniffiHandle)
            val makeCall = { ->
                uniffiObj.`onProgress`(
                    FfiConverterTypeTransferProgressDto.lift(`progress`),
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
            FfiConverterTypeTransferListener.handleMap.remove(handle)
        }
    }

    internal val vtable = UniffiVTableCallbackInterfaceTransferListener(
        `onProgress`,
        uniffiFree,
    )

    internal fun register(lib: UniffiLib) {
        lib.uniffi_luciola_uniffi_fn_init_callback_vtable_transferlistener(vtable)
    }
}

public object FfiConverterTypeTransferListener : FfiConverterCallbackInterface<TransferListener>()




public object FfiConverterOptionalUShort: FfiConverterRustBuffer<kotlin.UShort?> {
    override fun read(buf: ByteBuffer): kotlin.UShort? {
        if (buf.get().toInt() == 0) {
            return null
        }
        return FfiConverterUShort.read(buf)
    }

    override fun allocationSize(value: kotlin.UShort?): ULong {
        if (value == null) {
            return 1UL
        } else {
            return 1UL + FfiConverterUShort.allocationSize(value)
        }
    }

    override fun write(value: kotlin.UShort?, buf: ByteBuffer) {
        if (value == null) {
            buf.put(0)
        } else {
            buf.put(1)
            FfiConverterUShort.write(value, buf)
        }
    }
}




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




public object FfiConverterOptionalTypeTransferCancelHandle: FfiConverterRustBuffer<TransferCancelHandle?> {
    override fun read(buf: ByteBuffer): TransferCancelHandle? {
        if (buf.get().toInt() == 0) {
            return null
        }
        return FfiConverterTypeTransferCancelHandle.read(buf)
    }

    override fun allocationSize(value: TransferCancelHandle?): ULong {
        if (value == null) {
            return 1UL
        } else {
            return 1UL + FfiConverterTypeTransferCancelHandle.allocationSize(value)
        }
    }

    override fun write(value: TransferCancelHandle?, buf: ByteBuffer) {
        if (value == null) {
            buf.put(0)
        } else {
            buf.put(1)
            FfiConverterTypeTransferCancelHandle.write(value, buf)
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




public object FfiConverterOptionalTypeLanDialConfigDto: FfiConverterRustBuffer<LanDialConfigDto?> {
    override fun read(buf: ByteBuffer): LanDialConfigDto? {
        if (buf.get().toInt() == 0) {
            return null
        }
        return FfiConverterTypeLanDialConfigDto.read(buf)
    }

    override fun allocationSize(value: LanDialConfigDto?): ULong {
        if (value == null) {
            return 1UL
        } else {
            return 1UL + FfiConverterTypeLanDialConfigDto.allocationSize(value)
        }
    }

    override fun write(value: LanDialConfigDto?, buf: ByteBuffer) {
        if (value == null) {
            buf.put(0)
        } else {
            buf.put(1)
            FfiConverterTypeLanDialConfigDto.write(value, buf)
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




public object FfiConverterOptionalTypeWanConfig: FfiConverterRustBuffer<WanConfig?> {
    override fun read(buf: ByteBuffer): WanConfig? {
        if (buf.get().toInt() == 0) {
            return null
        }
        return FfiConverterTypeWanConfig.read(buf)
    }

    override fun allocationSize(value: WanConfig?): ULong {
        if (value == null) {
            return 1UL
        } else {
            return 1UL + FfiConverterTypeWanConfig.allocationSize(value)
        }
    }

    override fun write(value: WanConfig?, buf: ByteBuffer) {
        if (value == null) {
            buf.put(0)
        } else {
            buf.put(1)
            FfiConverterTypeWanConfig.write(value, buf)
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




public object FfiConverterOptionalTypeLogSink: FfiConverterRustBuffer<LogSink?> {
    override fun read(buf: ByteBuffer): LogSink? {
        if (buf.get().toInt() == 0) {
            return null
        }
        return FfiConverterTypeLogSink.read(buf)
    }

    override fun allocationSize(value: LogSink?): ULong {
        if (value == null) {
            return 1UL
        } else {
            return 1UL + FfiConverterTypeLogSink.allocationSize(value)
        }
    }

    override fun write(value: LogSink?, buf: ByteBuffer) {
        if (value == null) {
            buf.put(0)
        } else {
            buf.put(1)
            FfiConverterTypeLogSink.write(value, buf)
        }
    }
}




public object FfiConverterOptionalTypeTransferListener: FfiConverterRustBuffer<TransferListener?> {
    override fun read(buf: ByteBuffer): TransferListener? {
        if (buf.get().toInt() == 0) {
            return null
        }
        return FfiConverterTypeTransferListener.read(buf)
    }

    override fun allocationSize(value: TransferListener?): ULong {
        if (value == null) {
            return 1UL
        } else {
            return 1UL + FfiConverterTypeTransferListener.allocationSize(value)
        }
    }

    override fun write(value: TransferListener?, buf: ByteBuffer) {
        if (value == null) {
            buf.put(0)
        } else {
            buf.put(1)
            FfiConverterTypeTransferListener.write(value, buf)
        }
    }
}




public object FfiConverterOptionalSequenceString: FfiConverterRustBuffer<List<kotlin.String>?> {
    override fun read(buf: ByteBuffer): List<kotlin.String>? {
        if (buf.get().toInt() == 0) {
            return null
        }
        return FfiConverterSequenceString.read(buf)
    }

    override fun allocationSize(value: List<kotlin.String>?): ULong {
        if (value == null) {
            return 1UL
        } else {
            return 1UL + FfiConverterSequenceString.allocationSize(value)
        }
    }

    override fun write(value: List<kotlin.String>?, buf: ByteBuffer) {
        if (value == null) {
            buf.put(0)
        } else {
            buf.put(1)
            FfiConverterSequenceString.write(value, buf)
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




public object FfiConverterSequenceByteArray: FfiConverterRustBuffer<List<kotlin.ByteArray>> {
    override fun read(buf: ByteBuffer): List<kotlin.ByteArray> {
        val len = buf.getInt()
        return List<kotlin.ByteArray>(len) {
            FfiConverterByteArray.read(buf)
        }
    }

    override fun allocationSize(value: List<kotlin.ByteArray>): ULong {
        val sizeForLength = 4UL
        val sizeForItems = value.sumOf { FfiConverterByteArray.allocationSize(it) }
        return sizeForLength + sizeForItems
    }

    override fun write(value: List<kotlin.ByteArray>, buf: ByteBuffer) {
        buf.putInt(value.size)
        value.iterator().forEach {
            FfiConverterByteArray.write(it, buf)
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




public object FfiConverterSequenceTypeForwardRuleDto: FfiConverterRustBuffer<List<ForwardRuleDto>> {
    override fun read(buf: ByteBuffer): List<ForwardRuleDto> {
        val len = buf.getInt()
        return List<ForwardRuleDto>(len) {
            FfiConverterTypeForwardRuleDto.read(buf)
        }
    }

    override fun allocationSize(value: List<ForwardRuleDto>): ULong {
        val sizeForLength = 4UL
        val sizeForItems = value.sumOf { FfiConverterTypeForwardRuleDto.allocationSize(it) }
        return sizeForLength + sizeForItems
    }

    override fun write(value: List<ForwardRuleDto>, buf: ByteBuffer) {
        buf.putInt(value.size)
        value.iterator().forEach {
            FfiConverterTypeForwardRuleDto.write(it, buf)
        }
    }
}




public object FfiConverterSequenceTypeForwardStatusDto: FfiConverterRustBuffer<List<ForwardStatusDto>> {
    override fun read(buf: ByteBuffer): List<ForwardStatusDto> {
        val len = buf.getInt()
        return List<ForwardStatusDto>(len) {
            FfiConverterTypeForwardStatusDto.read(buf)
        }
    }

    override fun allocationSize(value: List<ForwardStatusDto>): ULong {
        val sizeForLength = 4UL
        val sizeForItems = value.sumOf { FfiConverterTypeForwardStatusDto.allocationSize(it) }
        return sizeForLength + sizeForItems
    }

    override fun write(value: List<ForwardStatusDto>, buf: ByteBuffer) {
        buf.putInt(value.size)
        value.iterator().forEach {
            FfiConverterTypeForwardStatusDto.write(it, buf)
        }
    }
}




public object FfiConverterSequenceTypeHubPeerInfoDto: FfiConverterRustBuffer<List<HubPeerInfoDto>> {
    override fun read(buf: ByteBuffer): List<HubPeerInfoDto> {
        val len = buf.getInt()
        return List<HubPeerInfoDto>(len) {
            FfiConverterTypeHubPeerInfoDto.read(buf)
        }
    }

    override fun allocationSize(value: List<HubPeerInfoDto>): ULong {
        val sizeForLength = 4UL
        val sizeForItems = value.sumOf { FfiConverterTypeHubPeerInfoDto.allocationSize(it) }
        return sizeForLength + sizeForItems
    }

    override fun write(value: List<HubPeerInfoDto>, buf: ByteBuffer) {
        buf.putInt(value.size)
        value.iterator().forEach {
            FfiConverterTypeHubPeerInfoDto.write(it, buf)
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

/**
 * Build the canonical `luciola://pair` URI (URL-encoded).
 */
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
 * Build a v3 `luciola://pair` URI (carrying optional PSK for WAN rendezvous).
 */
public actual fun `buildPairingUriV3`(`name`: kotlin.String, `product`: kotlin.String?, `port`: kotlin.UShort, `addrs`: List<kotlin.String>, `fingerprint`: kotlin.String?, `publicKey`: kotlin.String?, `pin`: kotlin.String?, `psk`: kotlin.String?): kotlin.String {
    return FfiConverterString.lift(uniffiRustCall { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_build_pairing_uri_v3(
            FfiConverterString.lower(`name`),
            FfiConverterOptionalString.lower(`product`),
            FfiConverterUShort.lower(`port`),
            FfiConverterSequenceString.lower(`addrs`),
            FfiConverterOptionalString.lower(`fingerprint`),
            FfiConverterOptionalString.lower(`publicKey`),
            FfiConverterOptionalString.lower(`pin`),
            FfiConverterOptionalString.lower(`psk`),
            uniffiRustCallStatus,
        )
    })
}

/**
 * Normalise either callback shape into one [`ErrorInfoDto`]:
 * - `classify_error(code, Some(message))` for `on_error`;
 * - `classify_error(detail, None)` for `on_state("error", detail)`, where the
 * detail is a `"<code>: <message>"` wire string.
 *
 * Legacy tunnel prefixes (`forward_bind_failed:`, `tunnel_*`) map to their
 * canonical codes; unrecognised text becomes `code = "unknown"` with the
 * full text preserved in `message`.
 */
public actual fun `classifyError`(`codeOrDetail`: kotlin.String, `message`: kotlin.String?): ErrorInfoDto {
    return FfiConverterTypeErrorInfoDto.lift(uniffiRustCall { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_classify_error(
            FfiConverterString.lower(`codeOrDetail`),
            FfiConverterOptionalString.lower(`message`),
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
 * Establish a WAN secure channel.
 *
 * Order of attempts: encrypted candidate exchange over WSS, simultaneous UDP
 * hole punching on the same socket, then an end-to-end encrypted relay over
 * the signalling WebSocket only when both peers allow it and agree on the
 * route. The returned channel reports the plane it actually uses.
 */
@Throws(WanFfiException::class)
public actual fun `connectWan`(`config`: WanConfig): WanChannel {
    return FfiConverterTypeWanChannel.lift(uniffiRustCallWithError(WanFfiExceptionErrorHandler) { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_connect_wan(
            FfiConverterTypeWanConfig.lower(`config`),
            uniffiRustCallStatus,
        )
    }!!)
}

/**
 * Establish an authenticated channel according to `policy` (`LanOnly`, `LanThenWan`, or `WanOnly`).
 *
 * When `policy` is [`RoutePolicyKind::LanThenWan`], `lan_budget_ms == 0` uses a 1500 ms default
 * budget. The returned [`WanChannel`] always reports the honest transport plane (`LanDirect`,
 * `HolePunchedDirect`, or `RelayForwarded`). Call from a worker thread, never from the UI thread.
 */
@Throws(WanFfiException::class)
public actual fun `connectWithPolicy`(`policy`: RoutePolicyKind, `lanBudgetMs`: kotlin.ULong, `lan`: LanDialConfigDto?, `wan`: WanConfig?): WanChannel {
    return FfiConverterTypeWanChannel.lift(uniffiRustCallWithError(WanFfiExceptionErrorHandler) { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_connect_with_policy(
            FfiConverterTypeRoutePolicyKind.lower(`policy`),
            FfiConverterULong.lower(`lanBudgetMs`),
            FfiConverterOptionalTypeLanDialConfigDto.lower(`lan`),
            FfiConverterOptionalTypeWanConfig.lower(`wan`),
            uniffiRustCallStatus,
        )
    }!!)
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
 * Derive a deterministic Cloudflare Worker rendezvous room ID from two public keys and an optional PSK.
 */
public actual fun `deriveRendezvousRoomId`(`myPk`: kotlin.String, `peerPk`: kotlin.String, `psk`: kotlin.String?, `epoch`: kotlin.ULong?): kotlin.String {
    return FfiConverterString.lift(uniffiRustCall { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_derive_rendezvous_room_id(
            FfiConverterString.lower(`myPk`),
            FfiConverterString.lower(`peerPk`),
            FfiConverterOptionalString.lower(`psk`),
            FfiConverterOptionalULong.lower(`epoch`),
            uniffiRustCallStatus,
        )
    })
}

/**
 * Every code in the error contract, in a stable order. Use this to validate
 * that a host handles the full set (and to detect a newer engine).
 */
public actual fun `errorCodes`(): List<kotlin.String> {
    return FfiConverterSequenceString.lift(uniffiRustCall { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_error_codes(
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

/**
 * Parse a pairing URI (`luciola://pair` v1/v2/v3 or plain `http://host:port`).
 */
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
 * Open one relay frame payload. Throws on tampering or a key/seq mismatch.
 */
@Throws(RelayCryptoException::class)
public actual fun `relayAeadOpen`(`key`: kotlin.ByteArray, `seq`: kotlin.ULong, `aad`: kotlin.ByteArray, `ciphertext`: kotlin.ByteArray): kotlin.ByteArray {
    return FfiConverterByteArray.lift(uniffiRustCallWithError(RelayCryptoExceptionErrorHandler) { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_relay_aead_open(
            FfiConverterByteArray.lower(`key`),
            FfiConverterULong.lower(`seq`),
            FfiConverterByteArray.lower(`aad`),
            FfiConverterByteArray.lower(`ciphertext`),
            uniffiRustCallStatus,
        )
    })
}

/**
 * Seal one relay frame payload (AES-256-GCM, AAD = the 12-byte frame header).
 */
public actual fun `relayAeadSeal`(`key`: kotlin.ByteArray, `seq`: kotlin.ULong, `aad`: kotlin.ByteArray, `plaintext`: kotlin.ByteArray): kotlin.ByteArray {
    return FfiConverterByteArray.lift(uniffiRustCall { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_relay_aead_seal(
            FfiConverterByteArray.lower(`key`),
            FfiConverterULong.lower(`seq`),
            FfiConverterByteArray.lower(`aad`),
            FfiConverterByteArray.lower(`plaintext`),
            uniffiRustCallStatus,
        )
    })
}

/**
 * Fresh X25519 ephemeral key pair for one relay session.
 */
public actual fun `relayEphemeralKeypair`(): RelayEphemeralKeyPair {
    return FfiConverterTypeRelayEphemeralKeyPair.lift(uniffiRustCall { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_relay_ephemeral_keypair(
            uniffiRustCallStatus,
        )
    })
}

/**
 * Public key for a (serialized) ephemeral secret.
 */
public actual fun `relayEphemeralPublic`(`secret`: kotlin.ByteArray): kotlin.ByteArray {
    return FfiConverterByteArray.lift(uniffiRustCall { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_relay_ephemeral_public(
            FfiConverterByteArray.lower(`secret`),
            uniffiRustCallStatus,
        )
    })
}

/**
 * Raw HKDF-SHA256, exported for the cross-language wire vectors.
 */
public actual fun `relayHkdfSha256`(`ikm`: kotlin.ByteArray, `salt`: kotlin.ByteArray, `info`: kotlin.ByteArray, `outLen`: kotlin.UInt): kotlin.ByteArray {
    return FfiConverterByteArray.lift(uniffiRustCall { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_relay_hkdf_sha256(
            FfiConverterByteArray.lower(`ikm`),
            FfiConverterByteArray.lower(`salt`),
            FfiConverterByteArray.lower(`info`),
            FfiConverterUInt.lower(`outLen`),
            uniffiRustCallStatus,
        )
    })
}

/**
 * Derive the two directional traffic keys for one relay session.
 */
public actual fun `relaySessionKeys`(`ephemeralSecret`: kotlin.ByteArray, `peerEphemeralPublic`: kotlin.ByteArray, `transcript`: kotlin.ByteArray, `initiatorFingerprint`: kotlin.String, `responderFingerprint`: kotlin.String, `isInitiator`: kotlin.Boolean): RelaySessionKeys {
    return FfiConverterTypeRelaySessionKeys.lift(uniffiRustCall { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_relay_session_keys(
            FfiConverterByteArray.lower(`ephemeralSecret`),
            FfiConverterByteArray.lower(`peerEphemeralPublic`),
            FfiConverterByteArray.lower(`transcript`),
            FfiConverterString.lower(`initiatorFingerprint`),
            FfiConverterString.lower(`responderFingerprint`),
            FfiConverterBoolean.lower(`isInitiator`),
            uniffiRustCallStatus,
        )
    })
}

/**
 * The byte string the Ed25519 handshake signature covers.
 *
 * Pass `ephemeral_public` only when the handshake carries the X25519
 * ephemeral key; legacy peers sign `"{timestamp_ms}:{node_id}"`.
 */
public actual fun `relaySignedHandshakePayload`(`timestampMs`: kotlin.ULong, `nodeId`: kotlin.String, `ephemeralPublic`: kotlin.ByteArray?): kotlin.String {
    return FfiConverterString.lift(uniffiRustCall { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_relay_signed_handshake_payload(
            FfiConverterULong.lower(`timestampMs`),
            FfiConverterString.lower(`nodeId`),
            FfiConverterOptionalByteArray.lower(`ephemeralPublic`),
            uniffiRustCallStatus,
        )
    })
}

/**
 * SHA-256 over both raw handshake byte strings, initiator first.
 */
public actual fun `relayTranscriptHash`(`initiatorHandshake`: kotlin.ByteArray, `responderHandshake`: kotlin.ByteArray): kotlin.ByteArray {
    return FfiConverterByteArray.lift(uniffiRustCall { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_relay_transcript_hash(
            FfiConverterByteArray.lower(`initiatorHandshake`),
            FfiConverterByteArray.lower(`responderHandshake`),
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
 * 安装（或替换）平台日志出口。传 `None` 仅清空出口，不卸载 subscriber
 * （全局 subscriber 无法卸载）。
 */
public actual fun `setLogSink`(`sink`: LogSink?) {
    uniffiRustCall { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_set_log_sink(
            FfiConverterOptionalTypeLogSink.lower(`sink`),
            uniffiRustCallStatus,
        )
    }
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
 * Accept one pin-verified LAN file transfer into `dest_dir` (no TOFU).
 * Call from a background worker thread.
 */
@Throws(TransferFfiException::class)
public actual fun `transferRecvLan`(`identitySeed`: kotlin.ByteArray, `listenPort`: kotlin.UShort, `acceptPeerPublicKey`: kotlin.ByteArray, `destDir`: kotlin.String, `listener`: TransferListener?, `cancel`: TransferCancelHandle?): TransferReceiptDto {
    return FfiConverterTypeTransferReceiptDto.lift(uniffiRustCallWithError(TransferFfiExceptionErrorHandler) { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_transfer_recv_lan(
            FfiConverterByteArray.lower(`identitySeed`),
            FfiConverterUShort.lower(`listenPort`),
            FfiConverterByteArray.lower(`acceptPeerPublicKey`),
            FfiConverterString.lower(`destDir`),
            FfiConverterOptionalTypeTransferListener.lower(`listener`),
            FfiConverterOptionalTypeTransferCancelHandle.lower(`cancel`),
            uniffiRustCallStatus,
        )
    })
}

/**
 * Receive one file over an already-established [`WanChannel`] (consumes the channel).
 */
@Throws(TransferFfiException::class)
public actual fun `transferRecvWan`(`channel`: WanChannel, `destDir`: kotlin.String, `listener`: TransferListener?, `cancel`: TransferCancelHandle?): TransferReceiptDto {
    return FfiConverterTypeTransferReceiptDto.lift(uniffiRustCallWithError(TransferFfiExceptionErrorHandler) { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_transfer_recv_wan(
            FfiConverterTypeWanChannel.lower(`channel`),
            FfiConverterString.lower(`destDir`),
            FfiConverterOptionalTypeTransferListener.lower(`listener`),
            FfiConverterOptionalTypeTransferCancelHandle.lower(`cancel`),
            uniffiRustCallStatus,
        )
    })
}

/**
 * Send one file over a pin-verified LAN connection (no TOFU).
 * Call from a background worker thread.
 */
@Throws(TransferFfiException::class)
public actual fun `transferSendLan`(`identitySeed`: kotlin.ByteArray, `addresses`: List<kotlin.String>, `port`: kotlin.UShort, `pinnedPeerPublicKey`: kotlin.ByteArray, `filePath`: kotlin.String, `listener`: TransferListener?, `cancel`: TransferCancelHandle?): TransferReceiptDto {
    return FfiConverterTypeTransferReceiptDto.lift(uniffiRustCallWithError(TransferFfiExceptionErrorHandler) { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_transfer_send_lan(
            FfiConverterByteArray.lower(`identitySeed`),
            FfiConverterSequenceString.lower(`addresses`),
            FfiConverterUShort.lower(`port`),
            FfiConverterByteArray.lower(`pinnedPeerPublicKey`),
            FfiConverterString.lower(`filePath`),
            FfiConverterOptionalTypeTransferListener.lower(`listener`),
            FfiConverterOptionalTypeTransferCancelHandle.lower(`cancel`),
            uniffiRustCallStatus,
        )
    })
}

/**
 * Send one file over an already-established [`WanChannel`] (consumes the channel).
 */
@Throws(TransferFfiException::class)
public actual fun `transferSendWan`(`channel`: WanChannel, `filePath`: kotlin.String, `maxRelayBytes`: kotlin.ULong?, `listener`: TransferListener?, `cancel`: TransferCancelHandle?): TransferReceiptDto {
    return FfiConverterTypeTransferReceiptDto.lift(uniffiRustCallWithError(TransferFfiExceptionErrorHandler) { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_transfer_send_wan(
            FfiConverterTypeWanChannel.lower(`channel`),
            FfiConverterString.lower(`filePath`),
            FfiConverterOptionalULong.lower(`maxRelayBytes`),
            FfiConverterOptionalTypeTransferListener.lower(`listener`),
            FfiConverterOptionalTypeTransferCancelHandle.lower(`cancel`),
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

/**
 * The current 10-minute rendezvous epoch (`unix_seconds / 600`).
 */
public actual fun `wanCurrentEpoch`(): kotlin.ULong {
    return FfiConverterULong.lift(uniffiRustCall { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_wan_current_epoch(
            uniffiRustCallStatus,
        )
    })
}

/**
 * Derive the room id both peers must use for `epoch`.
 *
 * The PSK is required: without one the engine returns an empty room id rather
 * than deriving a room any third party could predict from the two public keys.
 */
@Throws(WanFfiException::class)
public actual fun `wanDeriveRoomId`(`myPublicKey`: kotlin.ByteArray, `peerPublicKey`: kotlin.ByteArray, `psk`: kotlin.ByteArray, `epoch`: kotlin.ULong): kotlin.String {
    return FfiConverterString.lift(uniffiRustCallWithError(WanFfiExceptionErrorHandler) { uniffiRustCallStatus ->
        UniffiLib.uniffi_luciola_uniffi_fn_func_wan_derive_room_id(
            FfiConverterByteArray.lower(`myPublicKey`),
            FfiConverterByteArray.lower(`peerPublicKey`),
            FfiConverterByteArray.lower(`psk`),
            FfiConverterULong.lower(`epoch`),
            uniffiRustCallStatus,
        )
    })
}


// Async support