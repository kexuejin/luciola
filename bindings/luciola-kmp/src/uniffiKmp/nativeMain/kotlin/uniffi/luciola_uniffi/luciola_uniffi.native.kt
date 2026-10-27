

@file:Suppress("RemoveRedundantBackticks")
@file:OptIn(ExperimentalForeignApi::class)

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

import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.COpaquePointerVar
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.CValue
import kotlinx.cinterop.DoubleVar
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.FloatVar
import kotlinx.cinterop.IntVar
import kotlinx.cinterop.LongVar
import kotlinx.cinterop.ShortVar
import kotlinx.cinterop.get
import kotlinx.cinterop.pointed
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.set
import kotlinx.cinterop.staticCFunction
import kotlinx.cinterop.useContents
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.cValue
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.plus
import kotlinx.cinterop.ptr
import kotlinx.cinterop.readValue
import kotlinx.cinterop.toCPointer
import kotlinx.cinterop.usePinned
import kotlin.experimental.ExperimentalNativeApi
import kotlinx.cinterop.nativeHeap
import kotlinx.cinterop.value
import kotlinx.cinterop.CFunction
import kotlinx.cinterop.write
import kotlin.coroutines.resume
import platform.posix.memcpy
import kotlin.native.ref.createCleaner
import kotlinx.atomicfu.AtomicBoolean
import kotlinx.atomicfu.atomic
import kotlinx.cinterop.invoke


internal typealias Pointer = CPointer<out kotlinx.cinterop.CPointed>
internal val NullPointer: Pointer? = null
internal fun Pointer.toLong(): Long = rawValue.toLong()
internal fun kotlin.Long.toPointer(): Pointer = requireNotNull(this.toCPointer())


public class ByteBuffer(
    internal val pointer: CPointer<kotlinx.cinterop.ByteVar>,
    internal val capacity: Int,
    internal var position: Int = 0,
) {
    public fun position(): Int = position

    public fun hasRemaining(): Boolean = capacity != position

    private fun checkRemaining(bytes: Int) {
        val remaining = capacity - position
        require(bytes <= remaining) { 
            "buffer is exhausted: required: $bytes, remaining: $remaining, capacity: $capacity, position: $position" 
        }
    }

    public fun get(): Byte {
        checkRemaining(1)
        return pointer[position++]
    }

    public fun get(bytesToRead: Int): ByteArray {
        checkRemaining(bytesToRead)
        val result = ByteArray(bytesToRead)
        if (result.isNotEmpty()) {
            result.usePinned { pinned ->
                memcpy(pinned.addressOf(0), pointer + position, bytesToRead.convert())
            }
            position += bytesToRead
        }
        return result
    }

    public fun getShort(): Short {
        checkRemaining(2)
        return (((pointer[position++].toInt() and 0xff) shl 8)
                or (pointer[position++].toInt() and 0xff)).toShort()
    }

    public fun getInt(): Int {
        checkRemaining(4)
        return (((pointer[position++].toInt() and 0xff) shl 24)
                or ((pointer[position++].toInt() and 0xff) shl 16)
                or ((pointer[position++].toInt() and 0xff) shl 8)
                or (pointer[position++].toInt() and 0xff))
    }

    public fun getLong(): Long {
        checkRemaining(8)
        return (((pointer[position++].toLong() and 0xffL) shl 56)
                or ((pointer[position++].toLong() and 0xffL) shl 48)
                or ((pointer[position++].toLong() and 0xffL) shl 40)
                or ((pointer[position++].toLong() and 0xffL) shl 32)
                or ((pointer[position++].toLong() and 0xffL) shl 24)
                or ((pointer[position++].toLong() and 0xffL) shl 16)
                or ((pointer[position++].toLong() and 0xffL) shl 8)
                or (pointer[position++].toLong() and 0xffL))
    }

    public fun getFloat(): Float = Float.fromBits(getInt())

    public fun getDouble(): Double = Double.fromBits(getLong())

    public fun put(value: Byte) {
        checkRemaining(1)
        pointer[position++] = value
    }

    public fun put(src: ByteArray) {
        checkRemaining(src.size)
        if (src.isNotEmpty()) {
            src.usePinned { pinned ->
                memcpy(pointer + position, pinned.addressOf(0), src.size.convert())
            }
            position += src.size
        }
    }

    public fun putShort(value: Short) {
        checkRemaining(2)
        pointer[position++] = (value.toInt() ushr 8 and 0xff).toByte()
        pointer[position++] = (value.toInt() and 0xff).toByte()
    }

    public fun putInt(value: Int) {
        checkRemaining(4)
        pointer[position++] = (value ushr 24 and 0xff).toByte()
        pointer[position++] = (value ushr 16 and 0xff).toByte()
        pointer[position++] = (value ushr 8 and 0xff).toByte()
        pointer[position++] = (value and 0xff).toByte()
    }

    public fun putLong(value: Long) {
        checkRemaining(8)
        pointer[position++] = (value ushr 56 and 0xffL).toByte()
        pointer[position++] = (value ushr 48 and 0xffL).toByte()
        pointer[position++] = (value ushr 40 and 0xffL).toByte()
        pointer[position++] = (value ushr 32 and 0xffL).toByte()
        pointer[position++] = (value ushr 24 and 0xffL).toByte()
        pointer[position++] = (value ushr 16 and 0xffL).toByte()
        pointer[position++] = (value ushr 8 and 0xffL).toByte()
        pointer[position++] = (value and 0xffL).toByte()
    }

    public fun putFloat(value: Float): Unit = putInt(value.toRawBits())

    public fun putDouble(value: Double): Unit = putLong(value.toRawBits())
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

public typealias RustBuffer = CPointer<luciola_uniffi.cinterop.RustBuffer>

public var RustBuffer.capacity: Long
    get() = pointed.capacity
    set(value) { pointed.capacity = value }
public var RustBuffer.len: Long
    get() = pointed.len
    set(value) { pointed.len = value }
public var RustBuffer.data: Pointer?
    get() = pointed.data
    set(value) { pointed.data = value?.reinterpret() }
public fun RustBuffer.asByteBuffer(): ByteBuffer? {
    require(pointed.len <= Int.MAX_VALUE) {
        val length = pointed.len
        "cannot handle RustBuffer longer than Int.MAX_VALUE bytes: length is $length"
    }
    return ByteBuffer(
        pointed.data?.reinterpret<kotlinx.cinterop.ByteVar>() ?: return null,
        pointed.len.toInt(),
    )
}

public typealias RustBufferByValue = CValue<luciola_uniffi.cinterop.RustBuffer>
public fun RustBufferByValue(
    capacity: Long,
    len: Long,
    data: Pointer?,
): RustBufferByValue {
    return cValue<luciola_uniffi.cinterop.RustBuffer> {
        this.capacity = capacity
        this.len = len
        this.data = data?.reinterpret()
    }
}
public val RustBufferByValue.capacity: Long
    get() = useContents { capacity }
public val RustBufferByValue.len: Long
    get() = useContents { len }
public val RustBufferByValue.data: Pointer?
    get() = useContents { data }
public fun RustBufferByValue.asByteBuffer(): ByteBuffer? {
    require(len <= Int.MAX_VALUE) {
        val length = len
        "cannot handle RustBuffer longer than Int.MAX_VALUE bytes: length is $length"
    }
    return ByteBuffer(
        data?.reinterpret<kotlinx.cinterop.ByteVar>() ?: return null,
        len.toInt(),
    )
}

internal typealias ForeignBytes = CPointer<luciola_uniffi.cinterop.ForeignBytes>
internal var ForeignBytes.len: Int
    get() = pointed.len
    set(value) { pointed.len = value }
internal var ForeignBytes.data: Pointer?
    get() = pointed.data
    set(value) { pointed.data = value?.reinterpret() }

internal typealias ForeignBytesByValue = CValue<luciola_uniffi.cinterop.ForeignBytes>
internal val ForeignBytesByValue.len: Int
    get() = useContents { len }
internal val ForeignBytesByValue.data: Pointer?
    get() = useContents { data }

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

internal typealias UniffiRustCallStatus = CPointer<luciola_uniffi.cinterop.UniffiRustCallStatus>
internal var UniffiRustCallStatus.code: Byte
    get() = pointed.code
    set(value) { pointed.code = value }
internal var UniffiRustCallStatus.errorBuf: RustBufferByValue
    get() = pointed.errorBuf.readValue()
    set(value) { value.place(pointed.errorBuf.ptr) }

internal typealias UniffiRustCallStatusByValue = CValue<luciola_uniffi.cinterop.UniffiRustCallStatus>
internal fun UniffiRustCallStatusByValue(
    code: Byte,
    errorBuf: RustBufferByValue
): UniffiRustCallStatusByValue {
    return cValue<luciola_uniffi.cinterop.UniffiRustCallStatus> {
        this.code = code
        errorBuf.write(this.errorBuf.rawPtr)
    }
}
internal val UniffiRustCallStatusByValue.code: Byte
    get() = useContents { code }
internal val UniffiRustCallStatusByValue.errorBuf: RustBufferByValue
    get() = useContents { errorBuf.readValue() }

internal object UniffiRustCallStatusHelper {
    fun allocValue() = cValue<luciola_uniffi.cinterop.UniffiRustCallStatus>()
    fun <U> withReference(
        block: (UniffiRustCallStatus) -> U
    ): U {
        return memScoped {
            val status = alloc<luciola_uniffi.cinterop.UniffiRustCallStatus>()
            block(status.ptr)
        }
    }
}

internal class UniffiHandleMap<T: Any> {
    private val mapLock = kotlinx.atomicfu.locks.ReentrantLock()
    private val map = HashMap<Long, T>()

    // We'll start at 1L to prevent "Null Pointers" in native's `interpretCPointer`
    private val counter: kotlinx.atomicfu.AtomicLong = kotlinx.atomicfu.atomic(1L)

    internal val size: Int
        get() = map.size

    // Insert a new object into the handle map and get a handle for it
    internal fun insert(obj: T): Long {
        val handle = counter.getAndAdd(1)
        syncAccess { map.put(handle, obj) }
        return handle
    }

    // Get an object from the handle map
    internal fun get(handle: Long): T {
        return syncAccess { map.get(handle) } ?: throw InternalException("UniffiHandleMap.get: Invalid handle")
    }

    // Remove an entry from the handlemap and get the Kotlin object back
    internal fun remove(handle: Long): T {
        return syncAccess { map.remove(handle) } ?: throw InternalException("UniffiHandleMap.remove: Invalid handle")
    }

    internal fun <T> syncAccess(block: () -> T): T {
        mapLock.lock()
        try {
            return block()
        } finally {
            mapLock.unlock()
        }
    }
}

internal typealias ByteByReference = CPointer<ByteVar>
internal fun ByteByReference.setValue(value: Byte) {
    this.pointed.value = value
}
internal fun ByteByReference.getValue() : Byte {
    return this.pointed.value
}

internal typealias DoubleByReference = CPointer<DoubleVar>
internal fun DoubleByReference.setValue(value: Double) {
    this.pointed.value = value
}
internal fun DoubleByReference.getValue() : Double {
    return this.pointed.value
}

internal typealias FloatByReference = CPointer<FloatVar>
internal fun FloatByReference.setValue(value: Float) {
    this.pointed.value = value
}
internal fun FloatByReference.getValue() : Float {
    return this.pointed.value
}

internal typealias IntByReference = CPointer<IntVar>
internal fun IntByReference.setValue(value: Int) {
    this.pointed.value = value
}
internal fun IntByReference.getValue() : Int {
    return this.pointed.value
}

internal typealias LongByReference = CPointer<LongVar>
internal fun LongByReference.setValue(value: Long) {
    this.pointed.value = value
}
internal fun LongByReference.getValue() : Long {
    return this.pointed.value
}

internal typealias PointerByReference = CPointer<COpaquePointerVar>
internal fun PointerByReference.setValue(value: Pointer?) {
    this.pointed.value = value
}
internal fun PointerByReference.getValue(): Pointer? {
    return this.pointed.value
}

internal typealias ShortByReference = CPointer<ShortVar>
internal fun ShortByReference.setValue(value: Short) {
    this.pointed.value = value
}
internal fun ShortByReference.getValue(): Short {
    return this.pointed.value
}

// Contains loading, initialization code,
// and the FFI Function declarations.

internal typealias UniffiRustFutureContinuationCallback = luciola_uniffi.cinterop.UniffiRustFutureContinuationCallback
internal typealias UniffiForeignFutureFree = luciola_uniffi.cinterop.UniffiForeignFutureFree
internal typealias UniffiCallbackInterfaceFree = luciola_uniffi.cinterop.UniffiCallbackInterfaceFree
internal typealias UniffiForeignFuture = CPointer<luciola_uniffi.cinterop.UniffiForeignFuture>

internal var UniffiForeignFuture.`handle`: Long
    get() = pointed.`handle`
    set(value) {
        pointed.`handle` = value
    }

internal var UniffiForeignFuture.`free`: UniffiForeignFutureFree?
    get() = pointed.`free`
    set(value) {
        pointed.`free` = value
    }


internal fun UniffiForeignFuture.uniffiSetValue(other: UniffiForeignFuture) {
    `handle` = other.`handle`
    `free` = other.`free`
}
internal fun UniffiForeignFuture.uniffiSetValue(other: UniffiForeignFutureUniffiByValue) {
    `handle` = other.`handle`
    `free` = other.`free`
}

internal typealias UniffiForeignFutureUniffiByValue = CValue<luciola_uniffi.cinterop.UniffiForeignFuture>
internal fun UniffiForeignFutureUniffiByValue(
    `handle`: Long,
    `free`: UniffiForeignFutureFree?,
): UniffiForeignFutureUniffiByValue {
    return cValue<luciola_uniffi.cinterop.UniffiForeignFuture> {
        this.`handle` = `handle`
        this.`free` = `free`
    }
}


internal val UniffiForeignFutureUniffiByValue.`handle`: Long
    get() = useContents { `handle` }

internal val UniffiForeignFutureUniffiByValue.`free`: UniffiForeignFutureFree?
    get() = useContents { `free` }

internal typealias UniffiForeignFutureStructU8 = CPointer<luciola_uniffi.cinterop.UniffiForeignFutureStructU8>

internal var UniffiForeignFutureStructU8.`returnValue`: Byte
    get() = pointed.`returnValue`
    set(value) {
        pointed.`returnValue` = value
    }

internal var UniffiForeignFutureStructU8.`callStatus`: UniffiRustCallStatusByValue
    get() = pointed.`callStatus`.readValue()
    set(value) {
        value.write(pointed.`callStatus`.rawPtr)
    }


internal fun UniffiForeignFutureStructU8.uniffiSetValue(other: UniffiForeignFutureStructU8) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}
internal fun UniffiForeignFutureStructU8.uniffiSetValue(other: UniffiForeignFutureStructU8UniffiByValue) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}

internal typealias UniffiForeignFutureStructU8UniffiByValue = CValue<luciola_uniffi.cinterop.UniffiForeignFutureStructU8>
internal fun UniffiForeignFutureStructU8UniffiByValue(
    `returnValue`: Byte,
    `callStatus`: UniffiRustCallStatusByValue,
): UniffiForeignFutureStructU8UniffiByValue {
    return cValue<luciola_uniffi.cinterop.UniffiForeignFutureStructU8> {
        this.`returnValue` = `returnValue`
        `callStatus`.write(this.`callStatus`.rawPtr)
    }
}


internal val UniffiForeignFutureStructU8UniffiByValue.`returnValue`: Byte
    get() = useContents { `returnValue` }

internal val UniffiForeignFutureStructU8UniffiByValue.`callStatus`: UniffiRustCallStatusByValue
    get() = useContents { `callStatus`.readValue() }

internal typealias UniffiForeignFutureCompleteU8 = luciola_uniffi.cinterop.UniffiForeignFutureCompleteU8
internal typealias UniffiForeignFutureStructI8 = CPointer<luciola_uniffi.cinterop.UniffiForeignFutureStructI8>

internal var UniffiForeignFutureStructI8.`returnValue`: Byte
    get() = pointed.`returnValue`
    set(value) {
        pointed.`returnValue` = value
    }

internal var UniffiForeignFutureStructI8.`callStatus`: UniffiRustCallStatusByValue
    get() = pointed.`callStatus`.readValue()
    set(value) {
        value.write(pointed.`callStatus`.rawPtr)
    }


internal fun UniffiForeignFutureStructI8.uniffiSetValue(other: UniffiForeignFutureStructI8) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}
internal fun UniffiForeignFutureStructI8.uniffiSetValue(other: UniffiForeignFutureStructI8UniffiByValue) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}

internal typealias UniffiForeignFutureStructI8UniffiByValue = CValue<luciola_uniffi.cinterop.UniffiForeignFutureStructI8>
internal fun UniffiForeignFutureStructI8UniffiByValue(
    `returnValue`: Byte,
    `callStatus`: UniffiRustCallStatusByValue,
): UniffiForeignFutureStructI8UniffiByValue {
    return cValue<luciola_uniffi.cinterop.UniffiForeignFutureStructI8> {
        this.`returnValue` = `returnValue`
        `callStatus`.write(this.`callStatus`.rawPtr)
    }
}


internal val UniffiForeignFutureStructI8UniffiByValue.`returnValue`: Byte
    get() = useContents { `returnValue` }

internal val UniffiForeignFutureStructI8UniffiByValue.`callStatus`: UniffiRustCallStatusByValue
    get() = useContents { `callStatus`.readValue() }

internal typealias UniffiForeignFutureCompleteI8 = luciola_uniffi.cinterop.UniffiForeignFutureCompleteI8
internal typealias UniffiForeignFutureStructU16 = CPointer<luciola_uniffi.cinterop.UniffiForeignFutureStructU16>

internal var UniffiForeignFutureStructU16.`returnValue`: Short
    get() = pointed.`returnValue`
    set(value) {
        pointed.`returnValue` = value
    }

internal var UniffiForeignFutureStructU16.`callStatus`: UniffiRustCallStatusByValue
    get() = pointed.`callStatus`.readValue()
    set(value) {
        value.write(pointed.`callStatus`.rawPtr)
    }


internal fun UniffiForeignFutureStructU16.uniffiSetValue(other: UniffiForeignFutureStructU16) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}
internal fun UniffiForeignFutureStructU16.uniffiSetValue(other: UniffiForeignFutureStructU16UniffiByValue) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}

internal typealias UniffiForeignFutureStructU16UniffiByValue = CValue<luciola_uniffi.cinterop.UniffiForeignFutureStructU16>
internal fun UniffiForeignFutureStructU16UniffiByValue(
    `returnValue`: Short,
    `callStatus`: UniffiRustCallStatusByValue,
): UniffiForeignFutureStructU16UniffiByValue {
    return cValue<luciola_uniffi.cinterop.UniffiForeignFutureStructU16> {
        this.`returnValue` = `returnValue`
        `callStatus`.write(this.`callStatus`.rawPtr)
    }
}


internal val UniffiForeignFutureStructU16UniffiByValue.`returnValue`: Short
    get() = useContents { `returnValue` }

internal val UniffiForeignFutureStructU16UniffiByValue.`callStatus`: UniffiRustCallStatusByValue
    get() = useContents { `callStatus`.readValue() }

internal typealias UniffiForeignFutureCompleteU16 = luciola_uniffi.cinterop.UniffiForeignFutureCompleteU16
internal typealias UniffiForeignFutureStructI16 = CPointer<luciola_uniffi.cinterop.UniffiForeignFutureStructI16>

internal var UniffiForeignFutureStructI16.`returnValue`: Short
    get() = pointed.`returnValue`
    set(value) {
        pointed.`returnValue` = value
    }

internal var UniffiForeignFutureStructI16.`callStatus`: UniffiRustCallStatusByValue
    get() = pointed.`callStatus`.readValue()
    set(value) {
        value.write(pointed.`callStatus`.rawPtr)
    }


internal fun UniffiForeignFutureStructI16.uniffiSetValue(other: UniffiForeignFutureStructI16) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}
internal fun UniffiForeignFutureStructI16.uniffiSetValue(other: UniffiForeignFutureStructI16UniffiByValue) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}

internal typealias UniffiForeignFutureStructI16UniffiByValue = CValue<luciola_uniffi.cinterop.UniffiForeignFutureStructI16>
internal fun UniffiForeignFutureStructI16UniffiByValue(
    `returnValue`: Short,
    `callStatus`: UniffiRustCallStatusByValue,
): UniffiForeignFutureStructI16UniffiByValue {
    return cValue<luciola_uniffi.cinterop.UniffiForeignFutureStructI16> {
        this.`returnValue` = `returnValue`
        `callStatus`.write(this.`callStatus`.rawPtr)
    }
}


internal val UniffiForeignFutureStructI16UniffiByValue.`returnValue`: Short
    get() = useContents { `returnValue` }

internal val UniffiForeignFutureStructI16UniffiByValue.`callStatus`: UniffiRustCallStatusByValue
    get() = useContents { `callStatus`.readValue() }

internal typealias UniffiForeignFutureCompleteI16 = luciola_uniffi.cinterop.UniffiForeignFutureCompleteI16
internal typealias UniffiForeignFutureStructU32 = CPointer<luciola_uniffi.cinterop.UniffiForeignFutureStructU32>

internal var UniffiForeignFutureStructU32.`returnValue`: Int
    get() = pointed.`returnValue`
    set(value) {
        pointed.`returnValue` = value
    }

internal var UniffiForeignFutureStructU32.`callStatus`: UniffiRustCallStatusByValue
    get() = pointed.`callStatus`.readValue()
    set(value) {
        value.write(pointed.`callStatus`.rawPtr)
    }


internal fun UniffiForeignFutureStructU32.uniffiSetValue(other: UniffiForeignFutureStructU32) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}
internal fun UniffiForeignFutureStructU32.uniffiSetValue(other: UniffiForeignFutureStructU32UniffiByValue) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}

internal typealias UniffiForeignFutureStructU32UniffiByValue = CValue<luciola_uniffi.cinterop.UniffiForeignFutureStructU32>
internal fun UniffiForeignFutureStructU32UniffiByValue(
    `returnValue`: Int,
    `callStatus`: UniffiRustCallStatusByValue,
): UniffiForeignFutureStructU32UniffiByValue {
    return cValue<luciola_uniffi.cinterop.UniffiForeignFutureStructU32> {
        this.`returnValue` = `returnValue`
        `callStatus`.write(this.`callStatus`.rawPtr)
    }
}


internal val UniffiForeignFutureStructU32UniffiByValue.`returnValue`: Int
    get() = useContents { `returnValue` }

internal val UniffiForeignFutureStructU32UniffiByValue.`callStatus`: UniffiRustCallStatusByValue
    get() = useContents { `callStatus`.readValue() }

internal typealias UniffiForeignFutureCompleteU32 = luciola_uniffi.cinterop.UniffiForeignFutureCompleteU32
internal typealias UniffiForeignFutureStructI32 = CPointer<luciola_uniffi.cinterop.UniffiForeignFutureStructI32>

internal var UniffiForeignFutureStructI32.`returnValue`: Int
    get() = pointed.`returnValue`
    set(value) {
        pointed.`returnValue` = value
    }

internal var UniffiForeignFutureStructI32.`callStatus`: UniffiRustCallStatusByValue
    get() = pointed.`callStatus`.readValue()
    set(value) {
        value.write(pointed.`callStatus`.rawPtr)
    }


internal fun UniffiForeignFutureStructI32.uniffiSetValue(other: UniffiForeignFutureStructI32) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}
internal fun UniffiForeignFutureStructI32.uniffiSetValue(other: UniffiForeignFutureStructI32UniffiByValue) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}

internal typealias UniffiForeignFutureStructI32UniffiByValue = CValue<luciola_uniffi.cinterop.UniffiForeignFutureStructI32>
internal fun UniffiForeignFutureStructI32UniffiByValue(
    `returnValue`: Int,
    `callStatus`: UniffiRustCallStatusByValue,
): UniffiForeignFutureStructI32UniffiByValue {
    return cValue<luciola_uniffi.cinterop.UniffiForeignFutureStructI32> {
        this.`returnValue` = `returnValue`
        `callStatus`.write(this.`callStatus`.rawPtr)
    }
}


internal val UniffiForeignFutureStructI32UniffiByValue.`returnValue`: Int
    get() = useContents { `returnValue` }

internal val UniffiForeignFutureStructI32UniffiByValue.`callStatus`: UniffiRustCallStatusByValue
    get() = useContents { `callStatus`.readValue() }

internal typealias UniffiForeignFutureCompleteI32 = luciola_uniffi.cinterop.UniffiForeignFutureCompleteI32
internal typealias UniffiForeignFutureStructU64 = CPointer<luciola_uniffi.cinterop.UniffiForeignFutureStructU64>

internal var UniffiForeignFutureStructU64.`returnValue`: Long
    get() = pointed.`returnValue`
    set(value) {
        pointed.`returnValue` = value
    }

internal var UniffiForeignFutureStructU64.`callStatus`: UniffiRustCallStatusByValue
    get() = pointed.`callStatus`.readValue()
    set(value) {
        value.write(pointed.`callStatus`.rawPtr)
    }


internal fun UniffiForeignFutureStructU64.uniffiSetValue(other: UniffiForeignFutureStructU64) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}
internal fun UniffiForeignFutureStructU64.uniffiSetValue(other: UniffiForeignFutureStructU64UniffiByValue) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}

internal typealias UniffiForeignFutureStructU64UniffiByValue = CValue<luciola_uniffi.cinterop.UniffiForeignFutureStructU64>
internal fun UniffiForeignFutureStructU64UniffiByValue(
    `returnValue`: Long,
    `callStatus`: UniffiRustCallStatusByValue,
): UniffiForeignFutureStructU64UniffiByValue {
    return cValue<luciola_uniffi.cinterop.UniffiForeignFutureStructU64> {
        this.`returnValue` = `returnValue`
        `callStatus`.write(this.`callStatus`.rawPtr)
    }
}


internal val UniffiForeignFutureStructU64UniffiByValue.`returnValue`: Long
    get() = useContents { `returnValue` }

internal val UniffiForeignFutureStructU64UniffiByValue.`callStatus`: UniffiRustCallStatusByValue
    get() = useContents { `callStatus`.readValue() }

internal typealias UniffiForeignFutureCompleteU64 = luciola_uniffi.cinterop.UniffiForeignFutureCompleteU64
internal typealias UniffiForeignFutureStructI64 = CPointer<luciola_uniffi.cinterop.UniffiForeignFutureStructI64>

internal var UniffiForeignFutureStructI64.`returnValue`: Long
    get() = pointed.`returnValue`
    set(value) {
        pointed.`returnValue` = value
    }

internal var UniffiForeignFutureStructI64.`callStatus`: UniffiRustCallStatusByValue
    get() = pointed.`callStatus`.readValue()
    set(value) {
        value.write(pointed.`callStatus`.rawPtr)
    }


internal fun UniffiForeignFutureStructI64.uniffiSetValue(other: UniffiForeignFutureStructI64) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}
internal fun UniffiForeignFutureStructI64.uniffiSetValue(other: UniffiForeignFutureStructI64UniffiByValue) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}

internal typealias UniffiForeignFutureStructI64UniffiByValue = CValue<luciola_uniffi.cinterop.UniffiForeignFutureStructI64>
internal fun UniffiForeignFutureStructI64UniffiByValue(
    `returnValue`: Long,
    `callStatus`: UniffiRustCallStatusByValue,
): UniffiForeignFutureStructI64UniffiByValue {
    return cValue<luciola_uniffi.cinterop.UniffiForeignFutureStructI64> {
        this.`returnValue` = `returnValue`
        `callStatus`.write(this.`callStatus`.rawPtr)
    }
}


internal val UniffiForeignFutureStructI64UniffiByValue.`returnValue`: Long
    get() = useContents { `returnValue` }

internal val UniffiForeignFutureStructI64UniffiByValue.`callStatus`: UniffiRustCallStatusByValue
    get() = useContents { `callStatus`.readValue() }

internal typealias UniffiForeignFutureCompleteI64 = luciola_uniffi.cinterop.UniffiForeignFutureCompleteI64
internal typealias UniffiForeignFutureStructF32 = CPointer<luciola_uniffi.cinterop.UniffiForeignFutureStructF32>

internal var UniffiForeignFutureStructF32.`returnValue`: Float
    get() = pointed.`returnValue`
    set(value) {
        pointed.`returnValue` = value
    }

internal var UniffiForeignFutureStructF32.`callStatus`: UniffiRustCallStatusByValue
    get() = pointed.`callStatus`.readValue()
    set(value) {
        value.write(pointed.`callStatus`.rawPtr)
    }


internal fun UniffiForeignFutureStructF32.uniffiSetValue(other: UniffiForeignFutureStructF32) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}
internal fun UniffiForeignFutureStructF32.uniffiSetValue(other: UniffiForeignFutureStructF32UniffiByValue) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}

internal typealias UniffiForeignFutureStructF32UniffiByValue = CValue<luciola_uniffi.cinterop.UniffiForeignFutureStructF32>
internal fun UniffiForeignFutureStructF32UniffiByValue(
    `returnValue`: Float,
    `callStatus`: UniffiRustCallStatusByValue,
): UniffiForeignFutureStructF32UniffiByValue {
    return cValue<luciola_uniffi.cinterop.UniffiForeignFutureStructF32> {
        this.`returnValue` = `returnValue`
        `callStatus`.write(this.`callStatus`.rawPtr)
    }
}


internal val UniffiForeignFutureStructF32UniffiByValue.`returnValue`: Float
    get() = useContents { `returnValue` }

internal val UniffiForeignFutureStructF32UniffiByValue.`callStatus`: UniffiRustCallStatusByValue
    get() = useContents { `callStatus`.readValue() }

internal typealias UniffiForeignFutureCompleteF32 = luciola_uniffi.cinterop.UniffiForeignFutureCompleteF32
internal typealias UniffiForeignFutureStructF64 = CPointer<luciola_uniffi.cinterop.UniffiForeignFutureStructF64>

internal var UniffiForeignFutureStructF64.`returnValue`: Double
    get() = pointed.`returnValue`
    set(value) {
        pointed.`returnValue` = value
    }

internal var UniffiForeignFutureStructF64.`callStatus`: UniffiRustCallStatusByValue
    get() = pointed.`callStatus`.readValue()
    set(value) {
        value.write(pointed.`callStatus`.rawPtr)
    }


internal fun UniffiForeignFutureStructF64.uniffiSetValue(other: UniffiForeignFutureStructF64) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}
internal fun UniffiForeignFutureStructF64.uniffiSetValue(other: UniffiForeignFutureStructF64UniffiByValue) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}

internal typealias UniffiForeignFutureStructF64UniffiByValue = CValue<luciola_uniffi.cinterop.UniffiForeignFutureStructF64>
internal fun UniffiForeignFutureStructF64UniffiByValue(
    `returnValue`: Double,
    `callStatus`: UniffiRustCallStatusByValue,
): UniffiForeignFutureStructF64UniffiByValue {
    return cValue<luciola_uniffi.cinterop.UniffiForeignFutureStructF64> {
        this.`returnValue` = `returnValue`
        `callStatus`.write(this.`callStatus`.rawPtr)
    }
}


internal val UniffiForeignFutureStructF64UniffiByValue.`returnValue`: Double
    get() = useContents { `returnValue` }

internal val UniffiForeignFutureStructF64UniffiByValue.`callStatus`: UniffiRustCallStatusByValue
    get() = useContents { `callStatus`.readValue() }

internal typealias UniffiForeignFutureCompleteF64 = luciola_uniffi.cinterop.UniffiForeignFutureCompleteF64
internal typealias UniffiForeignFutureStructPointer = CPointer<luciola_uniffi.cinterop.UniffiForeignFutureStructPointer>

internal var UniffiForeignFutureStructPointer.`returnValue`: Pointer?
    get() = pointed.`returnValue`
    set(value) {
        pointed.`returnValue` = value
    }

internal var UniffiForeignFutureStructPointer.`callStatus`: UniffiRustCallStatusByValue
    get() = pointed.`callStatus`.readValue()
    set(value) {
        value.write(pointed.`callStatus`.rawPtr)
    }


internal fun UniffiForeignFutureStructPointer.uniffiSetValue(other: UniffiForeignFutureStructPointer) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}
internal fun UniffiForeignFutureStructPointer.uniffiSetValue(other: UniffiForeignFutureStructPointerUniffiByValue) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}

internal typealias UniffiForeignFutureStructPointerUniffiByValue = CValue<luciola_uniffi.cinterop.UniffiForeignFutureStructPointer>
internal fun UniffiForeignFutureStructPointerUniffiByValue(
    `returnValue`: Pointer?,
    `callStatus`: UniffiRustCallStatusByValue,
): UniffiForeignFutureStructPointerUniffiByValue {
    return cValue<luciola_uniffi.cinterop.UniffiForeignFutureStructPointer> {
        this.`returnValue` = `returnValue`
        `callStatus`.write(this.`callStatus`.rawPtr)
    }
}


internal val UniffiForeignFutureStructPointerUniffiByValue.`returnValue`: Pointer?
    get() = useContents { `returnValue` }

internal val UniffiForeignFutureStructPointerUniffiByValue.`callStatus`: UniffiRustCallStatusByValue
    get() = useContents { `callStatus`.readValue() }

internal typealias UniffiForeignFutureCompletePointer = luciola_uniffi.cinterop.UniffiForeignFutureCompletePointer
internal typealias UniffiForeignFutureStructRustBuffer = CPointer<luciola_uniffi.cinterop.UniffiForeignFutureStructRustBuffer>

internal var UniffiForeignFutureStructRustBuffer.`returnValue`: RustBufferByValue
    get() = pointed.`returnValue`.readValue()
    set(value) {
        value.write(pointed.`returnValue`.rawPtr)
    }

internal var UniffiForeignFutureStructRustBuffer.`callStatus`: UniffiRustCallStatusByValue
    get() = pointed.`callStatus`.readValue()
    set(value) {
        value.write(pointed.`callStatus`.rawPtr)
    }


internal fun UniffiForeignFutureStructRustBuffer.uniffiSetValue(other: UniffiForeignFutureStructRustBuffer) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}
internal fun UniffiForeignFutureStructRustBuffer.uniffiSetValue(other: UniffiForeignFutureStructRustBufferUniffiByValue) {
    `returnValue` = other.`returnValue`
    `callStatus` = other.`callStatus`
}

internal typealias UniffiForeignFutureStructRustBufferUniffiByValue = CValue<luciola_uniffi.cinterop.UniffiForeignFutureStructRustBuffer>
internal fun UniffiForeignFutureStructRustBufferUniffiByValue(
    `returnValue`: RustBufferByValue,
    `callStatus`: UniffiRustCallStatusByValue,
): UniffiForeignFutureStructRustBufferUniffiByValue {
    return cValue<luciola_uniffi.cinterop.UniffiForeignFutureStructRustBuffer> {
        `returnValue`.write(this.`returnValue`.rawPtr)
        `callStatus`.write(this.`callStatus`.rawPtr)
    }
}


internal val UniffiForeignFutureStructRustBufferUniffiByValue.`returnValue`: RustBufferByValue
    get() = useContents { `returnValue`.readValue() }

internal val UniffiForeignFutureStructRustBufferUniffiByValue.`callStatus`: UniffiRustCallStatusByValue
    get() = useContents { `callStatus`.readValue() }

internal typealias UniffiForeignFutureCompleteRustBuffer = luciola_uniffi.cinterop.UniffiForeignFutureCompleteRustBuffer
internal typealias UniffiForeignFutureStructVoid = CPointer<luciola_uniffi.cinterop.UniffiForeignFutureStructVoid>

internal var UniffiForeignFutureStructVoid.`callStatus`: UniffiRustCallStatusByValue
    get() = pointed.`callStatus`.readValue()
    set(value) {
        value.write(pointed.`callStatus`.rawPtr)
    }


internal fun UniffiForeignFutureStructVoid.uniffiSetValue(other: UniffiForeignFutureStructVoid) {
    `callStatus` = other.`callStatus`
}
internal fun UniffiForeignFutureStructVoid.uniffiSetValue(other: UniffiForeignFutureStructVoidUniffiByValue) {
    `callStatus` = other.`callStatus`
}

internal typealias UniffiForeignFutureStructVoidUniffiByValue = CValue<luciola_uniffi.cinterop.UniffiForeignFutureStructVoid>
internal fun UniffiForeignFutureStructVoidUniffiByValue(
    `callStatus`: UniffiRustCallStatusByValue,
): UniffiForeignFutureStructVoidUniffiByValue {
    return cValue<luciola_uniffi.cinterop.UniffiForeignFutureStructVoid> {
        `callStatus`.write(this.`callStatus`.rawPtr)
    }
}


internal val UniffiForeignFutureStructVoidUniffiByValue.`callStatus`: UniffiRustCallStatusByValue
    get() = useContents { `callStatus`.readValue() }

internal typealias UniffiForeignFutureCompleteVoid = luciola_uniffi.cinterop.UniffiForeignFutureCompleteVoid
internal typealias UniffiCallbackInterfaceOnPeerDiscoveredMethod0 = luciola_uniffi.cinterop.UniffiCallbackInterfaceOnPeerDiscoveredMethod0
internal typealias UniffiCallbackInterfaceOnPeerDiscoveredMethod1 = luciola_uniffi.cinterop.UniffiCallbackInterfaceOnPeerDiscoveredMethod1
internal typealias UniffiCallbackInterfaceOnPeerDiscoveredMethod2 = luciola_uniffi.cinterop.UniffiCallbackInterfaceOnPeerDiscoveredMethod2
internal typealias UniffiCallbackInterfaceOnPeerDiscoveredMethod3 = luciola_uniffi.cinterop.UniffiCallbackInterfaceOnPeerDiscoveredMethod3
internal typealias UniffiCallbackInterfaceSecureSessionListenerMethod0 = luciola_uniffi.cinterop.UniffiCallbackInterfaceSecureSessionListenerMethod0
internal typealias UniffiCallbackInterfaceSecureSessionListenerMethod1 = luciola_uniffi.cinterop.UniffiCallbackInterfaceSecureSessionListenerMethod1
internal typealias UniffiVTableCallbackInterfaceOnPeerDiscovered = CPointer<luciola_uniffi.cinterop.UniffiVTableCallbackInterfaceOnPeerDiscovered>

internal var UniffiVTableCallbackInterfaceOnPeerDiscovered.`onPeerDiscovered`: UniffiCallbackInterfaceOnPeerDiscoveredMethod0?
    get() = pointed.`onPeerDiscovered`
    set(value) {
        pointed.`onPeerDiscovered` = value
    }

internal var UniffiVTableCallbackInterfaceOnPeerDiscovered.`onPeerUpdated`: UniffiCallbackInterfaceOnPeerDiscoveredMethod1?
    get() = pointed.`onPeerUpdated`
    set(value) {
        pointed.`onPeerUpdated` = value
    }

internal var UniffiVTableCallbackInterfaceOnPeerDiscovered.`onPeerLost`: UniffiCallbackInterfaceOnPeerDiscoveredMethod2?
    get() = pointed.`onPeerLost`
    set(value) {
        pointed.`onPeerLost` = value
    }

internal var UniffiVTableCallbackInterfaceOnPeerDiscovered.`onError`: UniffiCallbackInterfaceOnPeerDiscoveredMethod3?
    get() = pointed.`onError`
    set(value) {
        pointed.`onError` = value
    }

internal var UniffiVTableCallbackInterfaceOnPeerDiscovered.`uniffiFree`: UniffiCallbackInterfaceFree?
    get() = pointed.`uniffiFree`
    set(value) {
        pointed.`uniffiFree` = value
    }


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

internal typealias UniffiVTableCallbackInterfaceOnPeerDiscoveredUniffiByValue = CValue<luciola_uniffi.cinterop.UniffiVTableCallbackInterfaceOnPeerDiscovered>
internal fun UniffiVTableCallbackInterfaceOnPeerDiscoveredUniffiByValue(
    `onPeerDiscovered`: UniffiCallbackInterfaceOnPeerDiscoveredMethod0?,
    `onPeerUpdated`: UniffiCallbackInterfaceOnPeerDiscoveredMethod1?,
    `onPeerLost`: UniffiCallbackInterfaceOnPeerDiscoveredMethod2?,
    `onError`: UniffiCallbackInterfaceOnPeerDiscoveredMethod3?,
    `uniffiFree`: UniffiCallbackInterfaceFree?,
): UniffiVTableCallbackInterfaceOnPeerDiscoveredUniffiByValue {
    return cValue<luciola_uniffi.cinterop.UniffiVTableCallbackInterfaceOnPeerDiscovered> {
        this.`onPeerDiscovered` = `onPeerDiscovered`
        this.`onPeerUpdated` = `onPeerUpdated`
        this.`onPeerLost` = `onPeerLost`
        this.`onError` = `onError`
        this.`uniffiFree` = `uniffiFree`
    }
}


internal val UniffiVTableCallbackInterfaceOnPeerDiscoveredUniffiByValue.`onPeerDiscovered`: UniffiCallbackInterfaceOnPeerDiscoveredMethod0?
    get() = useContents { `onPeerDiscovered` }

internal val UniffiVTableCallbackInterfaceOnPeerDiscoveredUniffiByValue.`onPeerUpdated`: UniffiCallbackInterfaceOnPeerDiscoveredMethod1?
    get() = useContents { `onPeerUpdated` }

internal val UniffiVTableCallbackInterfaceOnPeerDiscoveredUniffiByValue.`onPeerLost`: UniffiCallbackInterfaceOnPeerDiscoveredMethod2?
    get() = useContents { `onPeerLost` }

internal val UniffiVTableCallbackInterfaceOnPeerDiscoveredUniffiByValue.`onError`: UniffiCallbackInterfaceOnPeerDiscoveredMethod3?
    get() = useContents { `onError` }

internal val UniffiVTableCallbackInterfaceOnPeerDiscoveredUniffiByValue.`uniffiFree`: UniffiCallbackInterfaceFree?
    get() = useContents { `uniffiFree` }

internal typealias UniffiVTableCallbackInterfaceSecureSessionListener = CPointer<luciola_uniffi.cinterop.UniffiVTableCallbackInterfaceSecureSessionListener>

internal var UniffiVTableCallbackInterfaceSecureSessionListener.`onState`: UniffiCallbackInterfaceSecureSessionListenerMethod0?
    get() = pointed.`onState`
    set(value) {
        pointed.`onState` = value
    }

internal var UniffiVTableCallbackInterfaceSecureSessionListener.`onMessage`: UniffiCallbackInterfaceSecureSessionListenerMethod1?
    get() = pointed.`onMessage`
    set(value) {
        pointed.`onMessage` = value
    }

internal var UniffiVTableCallbackInterfaceSecureSessionListener.`uniffiFree`: UniffiCallbackInterfaceFree?
    get() = pointed.`uniffiFree`
    set(value) {
        pointed.`uniffiFree` = value
    }


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

internal typealias UniffiVTableCallbackInterfaceSecureSessionListenerUniffiByValue = CValue<luciola_uniffi.cinterop.UniffiVTableCallbackInterfaceSecureSessionListener>
internal fun UniffiVTableCallbackInterfaceSecureSessionListenerUniffiByValue(
    `onState`: UniffiCallbackInterfaceSecureSessionListenerMethod0?,
    `onMessage`: UniffiCallbackInterfaceSecureSessionListenerMethod1?,
    `uniffiFree`: UniffiCallbackInterfaceFree?,
): UniffiVTableCallbackInterfaceSecureSessionListenerUniffiByValue {
    return cValue<luciola_uniffi.cinterop.UniffiVTableCallbackInterfaceSecureSessionListener> {
        this.`onState` = `onState`
        this.`onMessage` = `onMessage`
        this.`uniffiFree` = `uniffiFree`
    }
}


internal val UniffiVTableCallbackInterfaceSecureSessionListenerUniffiByValue.`onState`: UniffiCallbackInterfaceSecureSessionListenerMethod0?
    get() = useContents { `onState` }

internal val UniffiVTableCallbackInterfaceSecureSessionListenerUniffiByValue.`onMessage`: UniffiCallbackInterfaceSecureSessionListenerMethod1?
    get() = useContents { `onMessage` }

internal val UniffiVTableCallbackInterfaceSecureSessionListenerUniffiByValue.`uniffiFree`: UniffiCallbackInterfaceFree?
    get() = useContents { `uniffiFree` }

































































































































































internal object UniffiLib {
    init {
            uniffiCallbackInterfaceOnPeerDiscovered.register(this)
            uniffiCallbackInterfaceSecureSessionListener.register(this)
    }
    // The Cleaner for the whole library
    internal val CLEANER: UniffiCleaner by lazy {
        UniffiCleaner.create()
    }

    fun uniffi_luciola_uniffi_fn_clone_discoverysession(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Pointer? = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_clone_discoverysession(
        `ptr`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_free_discoverysession(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_free_discoverysession(
        `ptr`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_constructor_discoverysession_new(
        `name`: RustBufferByValue,
        `port`: Short,
        `manualPeers`: RustBufferByValue,
        `product`: RustBufferByValue,
        `extra`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Pointer? = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_constructor_discoverysession_new(
        `name`,
        `port`,
        `manualPeers`,
        `product`,
        `extra`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_method_discoverysession_is_bound(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_method_discoverysession_is_bound(
        `ptr`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_method_discoverysession_node_id(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_method_discoverysession_node_id(
        `ptr`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_method_discoverysession_restart(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_method_discoverysession_restart(
        `ptr`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_method_discoverysession_seconds_since_idle(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Double = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_method_discoverysession_seconds_since_idle(
        `ptr`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_method_discoverysession_set_manual_peers(
        `ptr`: Pointer?,
        `peers`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_method_discoverysession_set_manual_peers(
        `ptr`,
        `peers`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_method_discoverysession_start(
        `ptr`: Pointer?,
        `listener`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_method_discoverysession_start(
        `ptr`,
        `listener`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_method_discoverysession_stop(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_method_discoverysession_stop(
        `ptr`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_clone_securesession(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Pointer? = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_clone_securesession(
        `ptr`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_free_securesession(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_free_securesession(
        `ptr`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_constructor_securesession_new(
        `identitySeed`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Pointer? = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_constructor_securesession_new(
        `identitySeed`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_method_securesession_connect(
        `ptr`: Pointer?,
        `addresses`: RustBufferByValue,
        `port`: Short,
        `pinnedPeerPublicKey`: RustBufferByValue,
        `autoReconnect`: Byte,
        `listener`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_method_securesession_connect(
        `ptr`,
        `addresses`,
        `port`,
        `pinnedPeerPublicKey`,
        `autoReconnect`,
        `listener`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_method_securesession_disconnect(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_method_securesession_disconnect(
        `ptr`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_method_securesession_is_connected(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_method_securesession_is_connected(
        `ptr`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_method_securesession_listen(
        `ptr`: Pointer?,
        `port`: Short,
        `expectedPeer`: RustBufferByValue,
        `listener`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_method_securesession_listen(
        `ptr`,
        `port`,
        `expectedPeer`,
        `listener`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_method_securesession_send(
        `ptr`: Pointer?,
        `message`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_method_securesession_send(
        `ptr`,
        `message`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_method_securesession_set_keepalive(
        `ptr`: Pointer?,
        `intervalMs`: Long,
        `deadAfterMs`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_method_securesession_set_keepalive(
        `ptr`,
        `intervalMs`,
        `deadAfterMs`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_method_securesession_set_retry_policy(
        `ptr`: Pointer?,
        `minMs`: Long,
        `maxMs`: Long,
        `jitterPct`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_method_securesession_set_retry_policy(
        `ptr`,
        `minMs`,
        `maxMs`,
        `jitterPct`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_method_securesession_stats(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_method_securesession_stats(
        `ptr`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_clone_truststore(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Pointer? = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_clone_truststore(
        `ptr`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_free_truststore(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_free_truststore(
        `ptr`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_constructor_truststore_new(
        `fromJson`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Pointer? = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_constructor_truststore_new(
        `fromJson`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_method_truststore_entries(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_method_truststore_entries(
        `ptr`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_method_truststore_level_of(
        `ptr`: Pointer?,
        `publicKey`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_method_truststore_level_of(
        `ptr`,
        `publicKey`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_method_truststore_remove(
        `ptr`: Pointer?,
        `fingerprint`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_method_truststore_remove(
        `ptr`,
        `fingerprint`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_method_truststore_to_json(
        `ptr`: Pointer?,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_method_truststore_to_json(
        `ptr`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_method_truststore_trust_device(
        `ptr`: Pointer?,
        `device`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_method_truststore_trust_device(
        `ptr`,
        `device`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_init_callback_vtable_onpeerdiscovered(
        `vtable`: UniffiVTableCallbackInterfaceOnPeerDiscovered,
    ): Unit = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_init_callback_vtable_onpeerdiscovered(
        `vtable`,
    )
    fun uniffi_luciola_uniffi_fn_init_callback_vtable_securesessionlistener(
        `vtable`: UniffiVTableCallbackInterfaceSecureSessionListener,
    ): Unit = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_init_callback_vtable_securesessionlistener(
        `vtable`,
    )
    fun uniffi_luciola_uniffi_fn_func_advertised_addresses(
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_func_advertised_addresses(
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_func_build_pairing_uri(
        `name`: RustBufferByValue,
        `product`: RustBufferByValue,
        `port`: Short,
        `addrs`: RustBufferByValue,
        `fingerprint`: RustBufferByValue,
        `publicKey`: RustBufferByValue,
        `pin`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_func_build_pairing_uri(
        `name`,
        `product`,
        `port`,
        `addrs`,
        `fingerprint`,
        `publicKey`,
        `pin`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_func_comparison_pin(
        `localPk`: RustBufferByValue,
        `remotePk`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_func_comparison_pin(
        `localPk`,
        `remotePk`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_func_default_race_candidates(
        `addresses`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_func_default_race_candidates(
        `addresses`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_func_generate_device_identity(
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_func_generate_device_identity(
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_func_get_device_meta(
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_func_get_device_meta(
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_func_identity_fingerprint(
        `publicKey`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_func_identity_fingerprint(
        `publicKey`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_func_identity_from_seed(
        `seed`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_func_identity_from_seed(
        `seed`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_func_identity_short_pin(
        `publicKey`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_func_identity_short_pin(
        `publicKey`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_func_is_lan_peer(
        `peerAddress`: RustBufferByValue,
        `localAddresses`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_func_is_lan_peer(
        `peerAddress`,
        `localAddresses`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_func_is_physical_nic(
        `name`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_func_is_physical_nic(
        `name`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_func_is_tun_virtual_ip(
        `address`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_func_is_tun_virtual_ip(
        `address`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_func_is_virtual_nic(
        `name`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_func_is_virtual_nic(
        `name`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_func_local_candidate_addresses(
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_func_local_candidate_addresses(
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_func_parse_pairing_uri(
        `uri`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_func_parse_pairing_uri(
        `uri`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_func_race_connect(
        `addresses`: RustBufferByValue,
        `port`: Short,
        `attemptTimeoutMs`: RustBufferByValue,
        `staggerMs`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_func_race_connect(
        `addresses`,
        `port`,
        `attemptTimeoutMs`,
        `staggerMs`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_func_render_qr_ascii(
        `content`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_func_render_qr_ascii(
        `content`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_func_select_lan_ip(
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_func_select_lan_ip(
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_func_sign_message(
        `seed`: RustBufferByValue,
        `message`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_func_sign_message(
        `seed`,
        `message`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_func_subnet_broadcast_addresses(
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_func_subnet_broadcast_addresses(
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_fn_func_verify_message(
        `publicKey`: RustBufferByValue,
        `message`: RustBufferByValue,
        `signature`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte = luciola_uniffi.cinterop.uniffi_luciola_uniffi_fn_func_verify_message(
        `publicKey`,
        `message`,
        `signature`,
        uniffiCallStatus,
    )
    fun ffi_luciola_uniffi_rustbuffer_alloc(
        `size`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue = luciola_uniffi.cinterop.ffi_luciola_uniffi_rustbuffer_alloc(
        `size`,
        uniffiCallStatus,
    )
    fun ffi_luciola_uniffi_rustbuffer_from_bytes(
        `bytes`: ForeignBytesByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue = luciola_uniffi.cinterop.ffi_luciola_uniffi_rustbuffer_from_bytes(
        `bytes`,
        uniffiCallStatus,
    )
    fun ffi_luciola_uniffi_rustbuffer_free(
        `buf`: RustBufferByValue,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rustbuffer_free(
        `buf`,
        uniffiCallStatus,
    )
    fun ffi_luciola_uniffi_rustbuffer_reserve(
        `buf`: RustBufferByValue,
        `additional`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue = luciola_uniffi.cinterop.ffi_luciola_uniffi_rustbuffer_reserve(
        `buf`,
        `additional`,
        uniffiCallStatus,
    )
    fun ffi_luciola_uniffi_rust_future_poll_u8(
        `handle`: Long,
        `callback`: UniffiRustFutureContinuationCallback,
        `callbackData`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_poll_u8(
        `handle`,
        `callback`,
        `callbackData`,
    )
    fun ffi_luciola_uniffi_rust_future_cancel_u8(
        `handle`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_cancel_u8(
        `handle`,
    )
    fun ffi_luciola_uniffi_rust_future_free_u8(
        `handle`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_free_u8(
        `handle`,
    )
    fun ffi_luciola_uniffi_rust_future_complete_u8(
        `handle`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_complete_u8(
        `handle`,
        uniffiCallStatus,
    )
    fun ffi_luciola_uniffi_rust_future_poll_i8(
        `handle`: Long,
        `callback`: UniffiRustFutureContinuationCallback,
        `callbackData`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_poll_i8(
        `handle`,
        `callback`,
        `callbackData`,
    )
    fun ffi_luciola_uniffi_rust_future_cancel_i8(
        `handle`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_cancel_i8(
        `handle`,
    )
    fun ffi_luciola_uniffi_rust_future_free_i8(
        `handle`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_free_i8(
        `handle`,
    )
    fun ffi_luciola_uniffi_rust_future_complete_i8(
        `handle`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Byte = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_complete_i8(
        `handle`,
        uniffiCallStatus,
    )
    fun ffi_luciola_uniffi_rust_future_poll_u16(
        `handle`: Long,
        `callback`: UniffiRustFutureContinuationCallback,
        `callbackData`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_poll_u16(
        `handle`,
        `callback`,
        `callbackData`,
    )
    fun ffi_luciola_uniffi_rust_future_cancel_u16(
        `handle`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_cancel_u16(
        `handle`,
    )
    fun ffi_luciola_uniffi_rust_future_free_u16(
        `handle`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_free_u16(
        `handle`,
    )
    fun ffi_luciola_uniffi_rust_future_complete_u16(
        `handle`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Short = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_complete_u16(
        `handle`,
        uniffiCallStatus,
    )
    fun ffi_luciola_uniffi_rust_future_poll_i16(
        `handle`: Long,
        `callback`: UniffiRustFutureContinuationCallback,
        `callbackData`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_poll_i16(
        `handle`,
        `callback`,
        `callbackData`,
    )
    fun ffi_luciola_uniffi_rust_future_cancel_i16(
        `handle`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_cancel_i16(
        `handle`,
    )
    fun ffi_luciola_uniffi_rust_future_free_i16(
        `handle`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_free_i16(
        `handle`,
    )
    fun ffi_luciola_uniffi_rust_future_complete_i16(
        `handle`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Short = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_complete_i16(
        `handle`,
        uniffiCallStatus,
    )
    fun ffi_luciola_uniffi_rust_future_poll_u32(
        `handle`: Long,
        `callback`: UniffiRustFutureContinuationCallback,
        `callbackData`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_poll_u32(
        `handle`,
        `callback`,
        `callbackData`,
    )
    fun ffi_luciola_uniffi_rust_future_cancel_u32(
        `handle`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_cancel_u32(
        `handle`,
    )
    fun ffi_luciola_uniffi_rust_future_free_u32(
        `handle`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_free_u32(
        `handle`,
    )
    fun ffi_luciola_uniffi_rust_future_complete_u32(
        `handle`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Int = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_complete_u32(
        `handle`,
        uniffiCallStatus,
    )
    fun ffi_luciola_uniffi_rust_future_poll_i32(
        `handle`: Long,
        `callback`: UniffiRustFutureContinuationCallback,
        `callbackData`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_poll_i32(
        `handle`,
        `callback`,
        `callbackData`,
    )
    fun ffi_luciola_uniffi_rust_future_cancel_i32(
        `handle`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_cancel_i32(
        `handle`,
    )
    fun ffi_luciola_uniffi_rust_future_free_i32(
        `handle`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_free_i32(
        `handle`,
    )
    fun ffi_luciola_uniffi_rust_future_complete_i32(
        `handle`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Int = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_complete_i32(
        `handle`,
        uniffiCallStatus,
    )
    fun ffi_luciola_uniffi_rust_future_poll_u64(
        `handle`: Long,
        `callback`: UniffiRustFutureContinuationCallback,
        `callbackData`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_poll_u64(
        `handle`,
        `callback`,
        `callbackData`,
    )
    fun ffi_luciola_uniffi_rust_future_cancel_u64(
        `handle`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_cancel_u64(
        `handle`,
    )
    fun ffi_luciola_uniffi_rust_future_free_u64(
        `handle`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_free_u64(
        `handle`,
    )
    fun ffi_luciola_uniffi_rust_future_complete_u64(
        `handle`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Long = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_complete_u64(
        `handle`,
        uniffiCallStatus,
    )
    fun ffi_luciola_uniffi_rust_future_poll_i64(
        `handle`: Long,
        `callback`: UniffiRustFutureContinuationCallback,
        `callbackData`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_poll_i64(
        `handle`,
        `callback`,
        `callbackData`,
    )
    fun ffi_luciola_uniffi_rust_future_cancel_i64(
        `handle`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_cancel_i64(
        `handle`,
    )
    fun ffi_luciola_uniffi_rust_future_free_i64(
        `handle`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_free_i64(
        `handle`,
    )
    fun ffi_luciola_uniffi_rust_future_complete_i64(
        `handle`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Long = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_complete_i64(
        `handle`,
        uniffiCallStatus,
    )
    fun ffi_luciola_uniffi_rust_future_poll_f32(
        `handle`: Long,
        `callback`: UniffiRustFutureContinuationCallback,
        `callbackData`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_poll_f32(
        `handle`,
        `callback`,
        `callbackData`,
    )
    fun ffi_luciola_uniffi_rust_future_cancel_f32(
        `handle`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_cancel_f32(
        `handle`,
    )
    fun ffi_luciola_uniffi_rust_future_free_f32(
        `handle`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_free_f32(
        `handle`,
    )
    fun ffi_luciola_uniffi_rust_future_complete_f32(
        `handle`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Float = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_complete_f32(
        `handle`,
        uniffiCallStatus,
    )
    fun ffi_luciola_uniffi_rust_future_poll_f64(
        `handle`: Long,
        `callback`: UniffiRustFutureContinuationCallback,
        `callbackData`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_poll_f64(
        `handle`,
        `callback`,
        `callbackData`,
    )
    fun ffi_luciola_uniffi_rust_future_cancel_f64(
        `handle`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_cancel_f64(
        `handle`,
    )
    fun ffi_luciola_uniffi_rust_future_free_f64(
        `handle`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_free_f64(
        `handle`,
    )
    fun ffi_luciola_uniffi_rust_future_complete_f64(
        `handle`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Double = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_complete_f64(
        `handle`,
        uniffiCallStatus,
    )
    fun ffi_luciola_uniffi_rust_future_poll_pointer(
        `handle`: Long,
        `callback`: UniffiRustFutureContinuationCallback,
        `callbackData`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_poll_pointer(
        `handle`,
        `callback`,
        `callbackData`,
    )
    fun ffi_luciola_uniffi_rust_future_cancel_pointer(
        `handle`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_cancel_pointer(
        `handle`,
    )
    fun ffi_luciola_uniffi_rust_future_free_pointer(
        `handle`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_free_pointer(
        `handle`,
    )
    fun ffi_luciola_uniffi_rust_future_complete_pointer(
        `handle`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Pointer? = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_complete_pointer(
        `handle`,
        uniffiCallStatus,
    )
    fun ffi_luciola_uniffi_rust_future_poll_rust_buffer(
        `handle`: Long,
        `callback`: UniffiRustFutureContinuationCallback,
        `callbackData`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_poll_rust_buffer(
        `handle`,
        `callback`,
        `callbackData`,
    )
    fun ffi_luciola_uniffi_rust_future_cancel_rust_buffer(
        `handle`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_cancel_rust_buffer(
        `handle`,
    )
    fun ffi_luciola_uniffi_rust_future_free_rust_buffer(
        `handle`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_free_rust_buffer(
        `handle`,
    )
    fun ffi_luciola_uniffi_rust_future_complete_rust_buffer(
        `handle`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): RustBufferByValue = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_complete_rust_buffer(
        `handle`,
        uniffiCallStatus,
    )
    fun ffi_luciola_uniffi_rust_future_poll_void(
        `handle`: Long,
        `callback`: UniffiRustFutureContinuationCallback,
        `callbackData`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_poll_void(
        `handle`,
        `callback`,
        `callbackData`,
    )
    fun ffi_luciola_uniffi_rust_future_cancel_void(
        `handle`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_cancel_void(
        `handle`,
    )
    fun ffi_luciola_uniffi_rust_future_free_void(
        `handle`: Long,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_free_void(
        `handle`,
    )
    fun ffi_luciola_uniffi_rust_future_complete_void(
        `handle`: Long,
        uniffiCallStatus: UniffiRustCallStatus,
    ): Unit = luciola_uniffi.cinterop.ffi_luciola_uniffi_rust_future_complete_void(
        `handle`,
        uniffiCallStatus,
    )
    fun uniffi_luciola_uniffi_checksum_func_advertised_addresses(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_func_advertised_addresses(
    )
    fun uniffi_luciola_uniffi_checksum_func_build_pairing_uri(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_func_build_pairing_uri(
    )
    fun uniffi_luciola_uniffi_checksum_func_comparison_pin(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_func_comparison_pin(
    )
    fun uniffi_luciola_uniffi_checksum_func_default_race_candidates(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_func_default_race_candidates(
    )
    fun uniffi_luciola_uniffi_checksum_func_generate_device_identity(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_func_generate_device_identity(
    )
    fun uniffi_luciola_uniffi_checksum_func_get_device_meta(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_func_get_device_meta(
    )
    fun uniffi_luciola_uniffi_checksum_func_identity_fingerprint(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_func_identity_fingerprint(
    )
    fun uniffi_luciola_uniffi_checksum_func_identity_from_seed(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_func_identity_from_seed(
    )
    fun uniffi_luciola_uniffi_checksum_func_identity_short_pin(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_func_identity_short_pin(
    )
    fun uniffi_luciola_uniffi_checksum_func_is_lan_peer(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_func_is_lan_peer(
    )
    fun uniffi_luciola_uniffi_checksum_func_is_physical_nic(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_func_is_physical_nic(
    )
    fun uniffi_luciola_uniffi_checksum_func_is_tun_virtual_ip(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_func_is_tun_virtual_ip(
    )
    fun uniffi_luciola_uniffi_checksum_func_is_virtual_nic(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_func_is_virtual_nic(
    )
    fun uniffi_luciola_uniffi_checksum_func_local_candidate_addresses(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_func_local_candidate_addresses(
    )
    fun uniffi_luciola_uniffi_checksum_func_parse_pairing_uri(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_func_parse_pairing_uri(
    )
    fun uniffi_luciola_uniffi_checksum_func_race_connect(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_func_race_connect(
    )
    fun uniffi_luciola_uniffi_checksum_func_render_qr_ascii(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_func_render_qr_ascii(
    )
    fun uniffi_luciola_uniffi_checksum_func_select_lan_ip(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_func_select_lan_ip(
    )
    fun uniffi_luciola_uniffi_checksum_func_sign_message(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_func_sign_message(
    )
    fun uniffi_luciola_uniffi_checksum_func_subnet_broadcast_addresses(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_func_subnet_broadcast_addresses(
    )
    fun uniffi_luciola_uniffi_checksum_func_verify_message(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_func_verify_message(
    )
    fun uniffi_luciola_uniffi_checksum_method_discoverysession_is_bound(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_method_discoverysession_is_bound(
    )
    fun uniffi_luciola_uniffi_checksum_method_discoverysession_node_id(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_method_discoverysession_node_id(
    )
    fun uniffi_luciola_uniffi_checksum_method_discoverysession_restart(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_method_discoverysession_restart(
    )
    fun uniffi_luciola_uniffi_checksum_method_discoverysession_seconds_since_idle(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_method_discoverysession_seconds_since_idle(
    )
    fun uniffi_luciola_uniffi_checksum_method_discoverysession_set_manual_peers(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_method_discoverysession_set_manual_peers(
    )
    fun uniffi_luciola_uniffi_checksum_method_discoverysession_start(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_method_discoverysession_start(
    )
    fun uniffi_luciola_uniffi_checksum_method_discoverysession_stop(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_method_discoverysession_stop(
    )
    fun uniffi_luciola_uniffi_checksum_method_securesession_connect(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_method_securesession_connect(
    )
    fun uniffi_luciola_uniffi_checksum_method_securesession_disconnect(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_method_securesession_disconnect(
    )
    fun uniffi_luciola_uniffi_checksum_method_securesession_is_connected(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_method_securesession_is_connected(
    )
    fun uniffi_luciola_uniffi_checksum_method_securesession_listen(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_method_securesession_listen(
    )
    fun uniffi_luciola_uniffi_checksum_method_securesession_send(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_method_securesession_send(
    )
    fun uniffi_luciola_uniffi_checksum_method_securesession_set_keepalive(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_method_securesession_set_keepalive(
    )
    fun uniffi_luciola_uniffi_checksum_method_securesession_set_retry_policy(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_method_securesession_set_retry_policy(
    )
    fun uniffi_luciola_uniffi_checksum_method_securesession_stats(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_method_securesession_stats(
    )
    fun uniffi_luciola_uniffi_checksum_method_truststore_entries(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_method_truststore_entries(
    )
    fun uniffi_luciola_uniffi_checksum_method_truststore_level_of(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_method_truststore_level_of(
    )
    fun uniffi_luciola_uniffi_checksum_method_truststore_remove(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_method_truststore_remove(
    )
    fun uniffi_luciola_uniffi_checksum_method_truststore_to_json(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_method_truststore_to_json(
    )
    fun uniffi_luciola_uniffi_checksum_method_truststore_trust_device(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_method_truststore_trust_device(
    )
    fun uniffi_luciola_uniffi_checksum_constructor_discoverysession_new(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_constructor_discoverysession_new(
    )
    fun uniffi_luciola_uniffi_checksum_constructor_securesession_new(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_constructor_securesession_new(
    )
    fun uniffi_luciola_uniffi_checksum_constructor_truststore_new(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_constructor_truststore_new(
    )
    fun uniffi_luciola_uniffi_checksum_method_onpeerdiscovered_on_peer_discovered(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_method_onpeerdiscovered_on_peer_discovered(
    )
    fun uniffi_luciola_uniffi_checksum_method_onpeerdiscovered_on_peer_updated(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_method_onpeerdiscovered_on_peer_updated(
    )
    fun uniffi_luciola_uniffi_checksum_method_onpeerdiscovered_on_peer_lost(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_method_onpeerdiscovered_on_peer_lost(
    )
    fun uniffi_luciola_uniffi_checksum_method_onpeerdiscovered_on_error(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_method_onpeerdiscovered_on_error(
    )
    fun uniffi_luciola_uniffi_checksum_method_securesessionlistener_on_state(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_method_securesessionlistener_on_state(
    )
    fun uniffi_luciola_uniffi_checksum_method_securesessionlistener_on_message(
    ): Short = luciola_uniffi.cinterop.uniffi_luciola_uniffi_checksum_method_securesessionlistener_on_message(
    )
    fun ffi_luciola_uniffi_uniffi_contract_version(
    ): Int = luciola_uniffi.cinterop.ffi_luciola_uniffi_uniffi_contract_version(
    )
    
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

private class NativeCleaner : UniffiCleaner {
    override fun register(resource: Any, disposable: Disposable): UniffiCleaner.Cleanable =
        // Ignore value here. In Kotlin/Native, if a cleaner object is referenced by the resource
        // object, both objects might leak and cleanupAction won't be called.
        //
        // Since this cleanable instance will be referenced by the resource instance, ignoring
        // the resource and making the cleaner only reference the disposable prevents the cleaner
        // from making a reference cycle thus able to destroy the disposable at a proper moment.
        UniffiNativeCleanable(disposable)
}

private class UniffiNativeCleanable(val disposable: Disposable) : UniffiCleaner.Cleanable {
    private val cleanAction = UniffiNativeCleanAction(disposable)

    @Suppress("unused")
    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = createCleaner(cleanAction, UniffiNativeCleanAction::clean)

    override fun clean() {
        cleanAction.clean()
    }

    private class UniffiNativeCleanAction(private val disposable: Disposable) {
        private val cleaned = atomic(false)
        fun clean() {
            if (cleaned.compareAndSet(false, true)) {
                disposable.destroy()
            }
        }
    }
}

private fun UniffiCleaner.Companion.create(): UniffiCleaner =
    NativeCleaner()


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
    internal fun `onPeerDiscovered`(
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
    
    internal fun `onPeerUpdated`(
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
    
    internal fun `onPeerLost`(
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
    
    internal fun `onError`(
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
    
    internal fun uniffiFree(handle: Long) {
        FfiConverterTypeOnPeerDiscovered.handleMap.remove(handle)
    }

    internal val vtable = nativeHeap.alloc<luciola_uniffi.cinterop.UniffiVTableCallbackInterfaceOnPeerDiscovered> {
        @Suppress("UNCHECKED_CAST")
        this.`onPeerDiscovered` = staticCFunction {
            `uniffiHandle`: Long,
            `peer`: RustBufferByValue,
            `uniffiOutReturn`: Pointer,
            uniffiCallStatus: UniffiRustCallStatus,
            ->
            uniffiCallbackInterfaceOnPeerDiscovered.`onPeerDiscovered`(
                `uniffiHandle`,
                `peer`,
                `uniffiOutReturn`,
                uniffiCallStatus,
            )
        } as luciola_uniffi.cinterop.UniffiCallbackInterfaceOnPeerDiscoveredMethod0
        @Suppress("UNCHECKED_CAST")
        this.`onPeerUpdated` = staticCFunction {
            `uniffiHandle`: Long,
            `peer`: RustBufferByValue,
            `uniffiOutReturn`: Pointer,
            uniffiCallStatus: UniffiRustCallStatus,
            ->
            uniffiCallbackInterfaceOnPeerDiscovered.`onPeerUpdated`(
                `uniffiHandle`,
                `peer`,
                `uniffiOutReturn`,
                uniffiCallStatus,
            )
        } as luciola_uniffi.cinterop.UniffiCallbackInterfaceOnPeerDiscoveredMethod1
        @Suppress("UNCHECKED_CAST")
        this.`onPeerLost` = staticCFunction {
            `uniffiHandle`: Long,
            `nodeId`: RustBufferByValue,
            `uniffiOutReturn`: Pointer,
            uniffiCallStatus: UniffiRustCallStatus,
            ->
            uniffiCallbackInterfaceOnPeerDiscovered.`onPeerLost`(
                `uniffiHandle`,
                `nodeId`,
                `uniffiOutReturn`,
                uniffiCallStatus,
            )
        } as luciola_uniffi.cinterop.UniffiCallbackInterfaceOnPeerDiscoveredMethod2
        @Suppress("UNCHECKED_CAST")
        this.`onError` = staticCFunction {
            `uniffiHandle`: Long,
            `code`: RustBufferByValue,
            `message`: RustBufferByValue,
            `uniffiOutReturn`: Pointer,
            uniffiCallStatus: UniffiRustCallStatus,
            ->
            uniffiCallbackInterfaceOnPeerDiscovered.`onError`(
                `uniffiHandle`,
                `code`,
                `message`,
                `uniffiOutReturn`,
                uniffiCallStatus,
            )
        } as luciola_uniffi.cinterop.UniffiCallbackInterfaceOnPeerDiscoveredMethod3
        this.uniffiFree = staticCFunction { handle: Long ->
            uniffiCallbackInterfaceOnPeerDiscovered.uniffiFree(handle)
        }
    }.ptr

    internal fun register(lib: UniffiLib) {
        lib.uniffi_luciola_uniffi_fn_init_callback_vtable_onpeerdiscovered(vtable)
    }
}

public object FfiConverterTypeOnPeerDiscovered : FfiConverterCallbackInterface<OnPeerDiscovered>()






// Put the implementation in an object so we don't pollute the top-level namespace
internal object uniffiCallbackInterfaceSecureSessionListener {
    internal fun `onState`(
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
    
    internal fun `onMessage`(
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
    
    internal fun uniffiFree(handle: Long) {
        FfiConverterTypeSecureSessionListener.handleMap.remove(handle)
    }

    internal val vtable = nativeHeap.alloc<luciola_uniffi.cinterop.UniffiVTableCallbackInterfaceSecureSessionListener> {
        @Suppress("UNCHECKED_CAST")
        this.`onState` = staticCFunction {
            `uniffiHandle`: Long,
            `state`: RustBufferByValue,
            `detail`: RustBufferByValue,
            `uniffiOutReturn`: Pointer,
            uniffiCallStatus: UniffiRustCallStatus,
            ->
            uniffiCallbackInterfaceSecureSessionListener.`onState`(
                `uniffiHandle`,
                `state`,
                `detail`,
                `uniffiOutReturn`,
                uniffiCallStatus,
            )
        } as luciola_uniffi.cinterop.UniffiCallbackInterfaceSecureSessionListenerMethod0
        @Suppress("UNCHECKED_CAST")
        this.`onMessage` = staticCFunction {
            `uniffiHandle`: Long,
            `message`: RustBufferByValue,
            `uniffiOutReturn`: Pointer,
            uniffiCallStatus: UniffiRustCallStatus,
            ->
            uniffiCallbackInterfaceSecureSessionListener.`onMessage`(
                `uniffiHandle`,
                `message`,
                `uniffiOutReturn`,
                uniffiCallStatus,
            )
        } as luciola_uniffi.cinterop.UniffiCallbackInterfaceSecureSessionListenerMethod1
        this.uniffiFree = staticCFunction { handle: Long ->
            uniffiCallbackInterfaceSecureSessionListener.uniffiFree(handle)
        }
    }.ptr

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