#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>


typedef struct RustBuffer
{
    int64_t capacity;
    int64_t len;
    uint8_t *_Nullable data;
} RustBuffer;

typedef struct ForeignBytes
{
    int32_t len;
    const uint8_t *_Nullable data;
} ForeignBytes;

typedef struct UniffiRustCallStatus {
  int8_t code;
  RustBuffer errorBuf;
} UniffiRustCallStatus;

// Public interface members begin here.


// Contains loading, initialization code,
// and the FFI Function declarations.

typedef void (*UniffiRustFutureContinuationCallback)(int64_t, int8_t
    );

typedef void (*UniffiForeignFutureFree)(int64_t
    );

typedef void (*UniffiCallbackInterfaceFree)(int64_t
    );

typedef struct UniffiForeignFuture {
    int64_t handle;
    UniffiForeignFutureFree free;
} UniffiForeignFuture;

typedef struct UniffiForeignFutureStructU8 {
    int8_t returnValue;
    UniffiRustCallStatus callStatus;
} UniffiForeignFutureStructU8;

typedef void (*UniffiForeignFutureCompleteU8)(int64_t, UniffiForeignFutureStructU8
    );

typedef struct UniffiForeignFutureStructI8 {
    int8_t returnValue;
    UniffiRustCallStatus callStatus;
} UniffiForeignFutureStructI8;

typedef void (*UniffiForeignFutureCompleteI8)(int64_t, UniffiForeignFutureStructI8
    );

typedef struct UniffiForeignFutureStructU16 {
    int16_t returnValue;
    UniffiRustCallStatus callStatus;
} UniffiForeignFutureStructU16;

typedef void (*UniffiForeignFutureCompleteU16)(int64_t, UniffiForeignFutureStructU16
    );

typedef struct UniffiForeignFutureStructI16 {
    int16_t returnValue;
    UniffiRustCallStatus callStatus;
} UniffiForeignFutureStructI16;

typedef void (*UniffiForeignFutureCompleteI16)(int64_t, UniffiForeignFutureStructI16
    );

typedef struct UniffiForeignFutureStructU32 {
    int32_t returnValue;
    UniffiRustCallStatus callStatus;
} UniffiForeignFutureStructU32;

typedef void (*UniffiForeignFutureCompleteU32)(int64_t, UniffiForeignFutureStructU32
    );

typedef struct UniffiForeignFutureStructI32 {
    int32_t returnValue;
    UniffiRustCallStatus callStatus;
} UniffiForeignFutureStructI32;

typedef void (*UniffiForeignFutureCompleteI32)(int64_t, UniffiForeignFutureStructI32
    );

typedef struct UniffiForeignFutureStructU64 {
    int64_t returnValue;
    UniffiRustCallStatus callStatus;
} UniffiForeignFutureStructU64;

typedef void (*UniffiForeignFutureCompleteU64)(int64_t, UniffiForeignFutureStructU64
    );

typedef struct UniffiForeignFutureStructI64 {
    int64_t returnValue;
    UniffiRustCallStatus callStatus;
} UniffiForeignFutureStructI64;

typedef void (*UniffiForeignFutureCompleteI64)(int64_t, UniffiForeignFutureStructI64
    );

typedef struct UniffiForeignFutureStructF32 {
    float returnValue;
    UniffiRustCallStatus callStatus;
} UniffiForeignFutureStructF32;

typedef void (*UniffiForeignFutureCompleteF32)(int64_t, UniffiForeignFutureStructF32
    );

typedef struct UniffiForeignFutureStructF64 {
    double returnValue;
    UniffiRustCallStatus callStatus;
} UniffiForeignFutureStructF64;

typedef void (*UniffiForeignFutureCompleteF64)(int64_t, UniffiForeignFutureStructF64
    );

typedef struct UniffiForeignFutureStructPointer {
    void * returnValue;
    UniffiRustCallStatus callStatus;
} UniffiForeignFutureStructPointer;

typedef void (*UniffiForeignFutureCompletePointer)(int64_t, UniffiForeignFutureStructPointer
    );

typedef struct UniffiForeignFutureStructRustBuffer {
    RustBuffer returnValue;
    UniffiRustCallStatus callStatus;
} UniffiForeignFutureStructRustBuffer;

typedef void (*UniffiForeignFutureCompleteRustBuffer)(int64_t, UniffiForeignFutureStructRustBuffer
    );

typedef struct UniffiForeignFutureStructVoid {
    UniffiRustCallStatus callStatus;
} UniffiForeignFutureStructVoid;

typedef void (*UniffiForeignFutureCompleteVoid)(int64_t, UniffiForeignFutureStructVoid
    );

typedef void (*UniffiCallbackInterfaceOnPeerDiscoveredMethod0)(int64_t, RustBuffer, void *, 
        UniffiRustCallStatus *_Nonnull uniffiCallStatus
    );

typedef void (*UniffiCallbackInterfaceOnPeerDiscoveredMethod1)(int64_t, RustBuffer, void *, 
        UniffiRustCallStatus *_Nonnull uniffiCallStatus
    );

typedef void (*UniffiCallbackInterfaceOnPeerDiscoveredMethod2)(int64_t, RustBuffer, void *, 
        UniffiRustCallStatus *_Nonnull uniffiCallStatus
    );

typedef void (*UniffiCallbackInterfaceOnPeerDiscoveredMethod3)(int64_t, RustBuffer, RustBuffer, void *, 
        UniffiRustCallStatus *_Nonnull uniffiCallStatus
    );

typedef void (*UniffiCallbackInterfaceSecureSessionListenerMethod0)(int64_t, RustBuffer, RustBuffer, void *, 
        UniffiRustCallStatus *_Nonnull uniffiCallStatus
    );

typedef void (*UniffiCallbackInterfaceSecureSessionListenerMethod1)(int64_t, RustBuffer, RustBuffer, RustBuffer, void *, 
        UniffiRustCallStatus *_Nonnull uniffiCallStatus
    );

typedef struct UniffiVTableCallbackInterfaceOnPeerDiscovered {
    UniffiCallbackInterfaceOnPeerDiscoveredMethod0 onPeerDiscovered;
    UniffiCallbackInterfaceOnPeerDiscoveredMethod1 onPeerUpdated;
    UniffiCallbackInterfaceOnPeerDiscoveredMethod2 onPeerLost;
    UniffiCallbackInterfaceOnPeerDiscoveredMethod3 onError;
    UniffiCallbackInterfaceFree uniffiFree;
} UniffiVTableCallbackInterfaceOnPeerDiscovered;

typedef struct UniffiVTableCallbackInterfaceSecureSessionListener {
    UniffiCallbackInterfaceSecureSessionListenerMethod0 onState;
    UniffiCallbackInterfaceSecureSessionListenerMethod1 onMessage;
    UniffiCallbackInterfaceFree uniffiFree;
} UniffiVTableCallbackInterfaceSecureSessionListener;

void * uniffi_luciola_uniffi_fn_clone_discoverysession(void * ptr, UniffiRustCallStatus *_Nonnull out_status
);
void uniffi_luciola_uniffi_fn_free_discoverysession(void * ptr, UniffiRustCallStatus *_Nonnull out_status
);
void * uniffi_luciola_uniffi_fn_constructor_discoverysession_new(RustBuffer name, int16_t port, RustBuffer manualPeers, RustBuffer product, RustBuffer extra, RustBuffer nodeId, RustBuffer tcpPort, RustBuffer publicKey, UniffiRustCallStatus *_Nonnull out_status
);
int8_t uniffi_luciola_uniffi_fn_method_discoverysession_is_bound(void * ptr, UniffiRustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_luciola_uniffi_fn_method_discoverysession_node_id(void * ptr, UniffiRustCallStatus *_Nonnull out_status
);
void uniffi_luciola_uniffi_fn_method_discoverysession_restart(void * ptr, UniffiRustCallStatus *_Nonnull out_status
);
double uniffi_luciola_uniffi_fn_method_discoverysession_seconds_since_idle(void * ptr, UniffiRustCallStatus *_Nonnull out_status
);
void uniffi_luciola_uniffi_fn_method_discoverysession_set_manual_peers(void * ptr, RustBuffer peers, UniffiRustCallStatus *_Nonnull out_status
);
void uniffi_luciola_uniffi_fn_method_discoverysession_start(void * ptr, int64_t listener, UniffiRustCallStatus *_Nonnull out_status
);
void uniffi_luciola_uniffi_fn_method_discoverysession_stop(void * ptr, UniffiRustCallStatus *_Nonnull out_status
);
void * uniffi_luciola_uniffi_fn_clone_securesession(void * ptr, UniffiRustCallStatus *_Nonnull out_status
);
void uniffi_luciola_uniffi_fn_free_securesession(void * ptr, UniffiRustCallStatus *_Nonnull out_status
);
void * uniffi_luciola_uniffi_fn_constructor_securesession_new(RustBuffer identitySeed, UniffiRustCallStatus *_Nonnull out_status
);
void uniffi_luciola_uniffi_fn_method_securesession_connect(void * ptr, RustBuffer addresses, int16_t port, RustBuffer pinnedPeerPublicKey, int8_t autoReconnect, int64_t listener, UniffiRustCallStatus *_Nonnull out_status
);
int8_t uniffi_luciola_uniffi_fn_method_securesession_disable_forward_endpoint(void * ptr, UniffiRustCallStatus *_Nonnull out_status
);
int8_t uniffi_luciola_uniffi_fn_method_securesession_disable_remote_endpoint(void * ptr, UniffiRustCallStatus *_Nonnull out_status
);
void uniffi_luciola_uniffi_fn_method_securesession_disconnect(void * ptr, UniffiRustCallStatus *_Nonnull out_status
);
int8_t uniffi_luciola_uniffi_fn_method_securesession_enable_forward_endpoint(void * ptr, RustBuffer rules, UniffiRustCallStatus *_Nonnull out_status
);
int8_t uniffi_luciola_uniffi_fn_method_securesession_enable_remote_endpoint(void * ptr, RustBuffer rules, UniffiRustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_luciola_uniffi_fn_method_securesession_forward_stats(void * ptr, UniffiRustCallStatus *_Nonnull out_status
);
int8_t uniffi_luciola_uniffi_fn_method_securesession_is_connected(void * ptr, UniffiRustCallStatus *_Nonnull out_status
);
void uniffi_luciola_uniffi_fn_method_securesession_listen(void * ptr, int16_t port, RustBuffer expectedPeer, int64_t listener, UniffiRustCallStatus *_Nonnull out_status
);
int8_t uniffi_luciola_uniffi_fn_method_securesession_send(void * ptr, RustBuffer message, UniffiRustCallStatus *_Nonnull out_status
);
void uniffi_luciola_uniffi_fn_method_securesession_set_keepalive(void * ptr, int64_t intervalMs, int64_t deadAfterMs, UniffiRustCallStatus *_Nonnull out_status
);
void uniffi_luciola_uniffi_fn_method_securesession_set_retry_policy(void * ptr, int64_t minMs, int64_t maxMs, int64_t jitterPct, UniffiRustCallStatus *_Nonnull out_status
);
void uniffi_luciola_uniffi_fn_method_securesession_set_tunnel_keepalive(void * ptr, int64_t intervalMs, int64_t deadAfterMs, UniffiRustCallStatus *_Nonnull out_status
);
int8_t uniffi_luciola_uniffi_fn_method_securesession_set_tunnel_port(void * ptr, int16_t port, UniffiRustCallStatus *_Nonnull out_status
);
int8_t uniffi_luciola_uniffi_fn_method_securesession_start_local_forward(void * ptr, int16_t listenPort, RustBuffer host, int16_t port, UniffiRustCallStatus *_Nonnull out_status
);
int8_t uniffi_luciola_uniffi_fn_method_securesession_start_remote_forward(void * ptr, int16_t listenPort, RustBuffer host, int16_t port, UniffiRustCallStatus *_Nonnull out_status
);
int8_t uniffi_luciola_uniffi_fn_method_securesession_start_udp_forward(void * ptr, int16_t listenPort, RustBuffer host, int16_t port, UniffiRustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_luciola_uniffi_fn_method_securesession_stats(void * ptr, UniffiRustCallStatus *_Nonnull out_status
);
int8_t uniffi_luciola_uniffi_fn_method_securesession_stop_local_forward(void * ptr, int16_t listenPort, UniffiRustCallStatus *_Nonnull out_status
);
int8_t uniffi_luciola_uniffi_fn_method_securesession_stop_remote_forward(void * ptr, int16_t listenPort, UniffiRustCallStatus *_Nonnull out_status
);
int8_t uniffi_luciola_uniffi_fn_method_securesession_stop_udp_forward(void * ptr, int16_t listenPort, UniffiRustCallStatus *_Nonnull out_status
);
void * uniffi_luciola_uniffi_fn_clone_truststore(void * ptr, UniffiRustCallStatus *_Nonnull out_status
);
void uniffi_luciola_uniffi_fn_free_truststore(void * ptr, UniffiRustCallStatus *_Nonnull out_status
);
void * uniffi_luciola_uniffi_fn_constructor_truststore_new(RustBuffer fromJson, UniffiRustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_luciola_uniffi_fn_method_truststore_entries(void * ptr, UniffiRustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_luciola_uniffi_fn_method_truststore_level_of(void * ptr, RustBuffer publicKey, UniffiRustCallStatus *_Nonnull out_status
);
int8_t uniffi_luciola_uniffi_fn_method_truststore_remove(void * ptr, RustBuffer fingerprint, UniffiRustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_luciola_uniffi_fn_method_truststore_to_json(void * ptr, UniffiRustCallStatus *_Nonnull out_status
);
void uniffi_luciola_uniffi_fn_method_truststore_trust_device(void * ptr, RustBuffer device, UniffiRustCallStatus *_Nonnull out_status
);
void uniffi_luciola_uniffi_fn_init_callback_vtable_onpeerdiscovered(UniffiVTableCallbackInterfaceOnPeerDiscovered const * vtable
);
void uniffi_luciola_uniffi_fn_init_callback_vtable_securesessionlistener(UniffiVTableCallbackInterfaceSecureSessionListener const * vtable
);
RustBuffer uniffi_luciola_uniffi_fn_func_advertised_addresses(UniffiRustCallStatus *_Nonnull out_status
    
);
RustBuffer uniffi_luciola_uniffi_fn_func_build_pairing_uri(RustBuffer name, RustBuffer product, int16_t port, RustBuffer addrs, RustBuffer fingerprint, RustBuffer publicKey, RustBuffer pin, UniffiRustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_luciola_uniffi_fn_func_comparison_pin(RustBuffer localPk, RustBuffer remotePk, UniffiRustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_luciola_uniffi_fn_func_default_race_candidates(RustBuffer addresses, UniffiRustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_luciola_uniffi_fn_func_generate_device_identity(UniffiRustCallStatus *_Nonnull out_status
    
);
RustBuffer uniffi_luciola_uniffi_fn_func_get_device_meta(UniffiRustCallStatus *_Nonnull out_status
    
);
RustBuffer uniffi_luciola_uniffi_fn_func_identity_fingerprint(RustBuffer publicKey, UniffiRustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_luciola_uniffi_fn_func_identity_from_seed(RustBuffer seed, UniffiRustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_luciola_uniffi_fn_func_identity_short_pin(RustBuffer publicKey, UniffiRustCallStatus *_Nonnull out_status
);
int8_t uniffi_luciola_uniffi_fn_func_is_lan_peer(RustBuffer peerAddress, RustBuffer localAddresses, UniffiRustCallStatus *_Nonnull out_status
);
int8_t uniffi_luciola_uniffi_fn_func_is_physical_nic(RustBuffer name, UniffiRustCallStatus *_Nonnull out_status
);
int8_t uniffi_luciola_uniffi_fn_func_is_tun_virtual_ip(RustBuffer address, UniffiRustCallStatus *_Nonnull out_status
);
int8_t uniffi_luciola_uniffi_fn_func_is_virtual_nic(RustBuffer name, UniffiRustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_luciola_uniffi_fn_func_local_candidate_addresses(UniffiRustCallStatus *_Nonnull out_status
    
);
RustBuffer uniffi_luciola_uniffi_fn_func_parse_pairing_uri(RustBuffer uri, UniffiRustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_luciola_uniffi_fn_func_race_connect(RustBuffer addresses, int16_t port, RustBuffer attemptTimeoutMs, RustBuffer staggerMs, UniffiRustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_luciola_uniffi_fn_func_render_qr_ascii(RustBuffer content, UniffiRustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_luciola_uniffi_fn_func_select_lan_ip(UniffiRustCallStatus *_Nonnull out_status
    
);
RustBuffer uniffi_luciola_uniffi_fn_func_sign_message(RustBuffer seed, RustBuffer message, UniffiRustCallStatus *_Nonnull out_status
);
RustBuffer uniffi_luciola_uniffi_fn_func_subnet_broadcast_addresses(UniffiRustCallStatus *_Nonnull out_status
    
);
int8_t uniffi_luciola_uniffi_fn_func_verify_message(RustBuffer publicKey, RustBuffer message, RustBuffer signature, UniffiRustCallStatus *_Nonnull out_status
);
RustBuffer ffi_luciola_uniffi_rustbuffer_alloc(int64_t size, UniffiRustCallStatus *_Nonnull out_status
);
RustBuffer ffi_luciola_uniffi_rustbuffer_from_bytes(ForeignBytes bytes, UniffiRustCallStatus *_Nonnull out_status
);
void ffi_luciola_uniffi_rustbuffer_free(RustBuffer buf, UniffiRustCallStatus *_Nonnull out_status
);
RustBuffer ffi_luciola_uniffi_rustbuffer_reserve(RustBuffer buf, int64_t additional, UniffiRustCallStatus *_Nonnull out_status
);
void ffi_luciola_uniffi_rust_future_poll_u8(int64_t handle, UniffiRustFutureContinuationCallback callback, int64_t callbackData
);
void ffi_luciola_uniffi_rust_future_cancel_u8(int64_t handle
);
void ffi_luciola_uniffi_rust_future_free_u8(int64_t handle
);
int8_t ffi_luciola_uniffi_rust_future_complete_u8(int64_t handle, UniffiRustCallStatus *_Nonnull out_status
);
void ffi_luciola_uniffi_rust_future_poll_i8(int64_t handle, UniffiRustFutureContinuationCallback callback, int64_t callbackData
);
void ffi_luciola_uniffi_rust_future_cancel_i8(int64_t handle
);
void ffi_luciola_uniffi_rust_future_free_i8(int64_t handle
);
int8_t ffi_luciola_uniffi_rust_future_complete_i8(int64_t handle, UniffiRustCallStatus *_Nonnull out_status
);
void ffi_luciola_uniffi_rust_future_poll_u16(int64_t handle, UniffiRustFutureContinuationCallback callback, int64_t callbackData
);
void ffi_luciola_uniffi_rust_future_cancel_u16(int64_t handle
);
void ffi_luciola_uniffi_rust_future_free_u16(int64_t handle
);
int16_t ffi_luciola_uniffi_rust_future_complete_u16(int64_t handle, UniffiRustCallStatus *_Nonnull out_status
);
void ffi_luciola_uniffi_rust_future_poll_i16(int64_t handle, UniffiRustFutureContinuationCallback callback, int64_t callbackData
);
void ffi_luciola_uniffi_rust_future_cancel_i16(int64_t handle
);
void ffi_luciola_uniffi_rust_future_free_i16(int64_t handle
);
int16_t ffi_luciola_uniffi_rust_future_complete_i16(int64_t handle, UniffiRustCallStatus *_Nonnull out_status
);
void ffi_luciola_uniffi_rust_future_poll_u32(int64_t handle, UniffiRustFutureContinuationCallback callback, int64_t callbackData
);
void ffi_luciola_uniffi_rust_future_cancel_u32(int64_t handle
);
void ffi_luciola_uniffi_rust_future_free_u32(int64_t handle
);
int32_t ffi_luciola_uniffi_rust_future_complete_u32(int64_t handle, UniffiRustCallStatus *_Nonnull out_status
);
void ffi_luciola_uniffi_rust_future_poll_i32(int64_t handle, UniffiRustFutureContinuationCallback callback, int64_t callbackData
);
void ffi_luciola_uniffi_rust_future_cancel_i32(int64_t handle
);
void ffi_luciola_uniffi_rust_future_free_i32(int64_t handle
);
int32_t ffi_luciola_uniffi_rust_future_complete_i32(int64_t handle, UniffiRustCallStatus *_Nonnull out_status
);
void ffi_luciola_uniffi_rust_future_poll_u64(int64_t handle, UniffiRustFutureContinuationCallback callback, int64_t callbackData
);
void ffi_luciola_uniffi_rust_future_cancel_u64(int64_t handle
);
void ffi_luciola_uniffi_rust_future_free_u64(int64_t handle
);
int64_t ffi_luciola_uniffi_rust_future_complete_u64(int64_t handle, UniffiRustCallStatus *_Nonnull out_status
);
void ffi_luciola_uniffi_rust_future_poll_i64(int64_t handle, UniffiRustFutureContinuationCallback callback, int64_t callbackData
);
void ffi_luciola_uniffi_rust_future_cancel_i64(int64_t handle
);
void ffi_luciola_uniffi_rust_future_free_i64(int64_t handle
);
int64_t ffi_luciola_uniffi_rust_future_complete_i64(int64_t handle, UniffiRustCallStatus *_Nonnull out_status
);
void ffi_luciola_uniffi_rust_future_poll_f32(int64_t handle, UniffiRustFutureContinuationCallback callback, int64_t callbackData
);
void ffi_luciola_uniffi_rust_future_cancel_f32(int64_t handle
);
void ffi_luciola_uniffi_rust_future_free_f32(int64_t handle
);
float ffi_luciola_uniffi_rust_future_complete_f32(int64_t handle, UniffiRustCallStatus *_Nonnull out_status
);
void ffi_luciola_uniffi_rust_future_poll_f64(int64_t handle, UniffiRustFutureContinuationCallback callback, int64_t callbackData
);
void ffi_luciola_uniffi_rust_future_cancel_f64(int64_t handle
);
void ffi_luciola_uniffi_rust_future_free_f64(int64_t handle
);
double ffi_luciola_uniffi_rust_future_complete_f64(int64_t handle, UniffiRustCallStatus *_Nonnull out_status
);
void ffi_luciola_uniffi_rust_future_poll_pointer(int64_t handle, UniffiRustFutureContinuationCallback callback, int64_t callbackData
);
void ffi_luciola_uniffi_rust_future_cancel_pointer(int64_t handle
);
void ffi_luciola_uniffi_rust_future_free_pointer(int64_t handle
);
void * ffi_luciola_uniffi_rust_future_complete_pointer(int64_t handle, UniffiRustCallStatus *_Nonnull out_status
);
void ffi_luciola_uniffi_rust_future_poll_rust_buffer(int64_t handle, UniffiRustFutureContinuationCallback callback, int64_t callbackData
);
void ffi_luciola_uniffi_rust_future_cancel_rust_buffer(int64_t handle
);
void ffi_luciola_uniffi_rust_future_free_rust_buffer(int64_t handle
);
RustBuffer ffi_luciola_uniffi_rust_future_complete_rust_buffer(int64_t handle, UniffiRustCallStatus *_Nonnull out_status
);
void ffi_luciola_uniffi_rust_future_poll_void(int64_t handle, UniffiRustFutureContinuationCallback callback, int64_t callbackData
);
void ffi_luciola_uniffi_rust_future_cancel_void(int64_t handle
);
void ffi_luciola_uniffi_rust_future_free_void(int64_t handle
);
void ffi_luciola_uniffi_rust_future_complete_void(int64_t handle, UniffiRustCallStatus *_Nonnull out_status
);
int16_t uniffi_luciola_uniffi_checksum_func_advertised_addresses(void
    
);
int16_t uniffi_luciola_uniffi_checksum_func_build_pairing_uri(void
    
);
int16_t uniffi_luciola_uniffi_checksum_func_comparison_pin(void
    
);
int16_t uniffi_luciola_uniffi_checksum_func_default_race_candidates(void
    
);
int16_t uniffi_luciola_uniffi_checksum_func_generate_device_identity(void
    
);
int16_t uniffi_luciola_uniffi_checksum_func_get_device_meta(void
    
);
int16_t uniffi_luciola_uniffi_checksum_func_identity_fingerprint(void
    
);
int16_t uniffi_luciola_uniffi_checksum_func_identity_from_seed(void
    
);
int16_t uniffi_luciola_uniffi_checksum_func_identity_short_pin(void
    
);
int16_t uniffi_luciola_uniffi_checksum_func_is_lan_peer(void
    
);
int16_t uniffi_luciola_uniffi_checksum_func_is_physical_nic(void
    
);
int16_t uniffi_luciola_uniffi_checksum_func_is_tun_virtual_ip(void
    
);
int16_t uniffi_luciola_uniffi_checksum_func_is_virtual_nic(void
    
);
int16_t uniffi_luciola_uniffi_checksum_func_local_candidate_addresses(void
    
);
int16_t uniffi_luciola_uniffi_checksum_func_parse_pairing_uri(void
    
);
int16_t uniffi_luciola_uniffi_checksum_func_race_connect(void
    
);
int16_t uniffi_luciola_uniffi_checksum_func_render_qr_ascii(void
    
);
int16_t uniffi_luciola_uniffi_checksum_func_select_lan_ip(void
    
);
int16_t uniffi_luciola_uniffi_checksum_func_sign_message(void
    
);
int16_t uniffi_luciola_uniffi_checksum_func_subnet_broadcast_addresses(void
    
);
int16_t uniffi_luciola_uniffi_checksum_func_verify_message(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_discoverysession_is_bound(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_discoverysession_node_id(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_discoverysession_restart(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_discoverysession_seconds_since_idle(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_discoverysession_set_manual_peers(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_discoverysession_start(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_discoverysession_stop(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_securesession_connect(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_securesession_disable_forward_endpoint(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_securesession_disable_remote_endpoint(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_securesession_disconnect(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_securesession_enable_forward_endpoint(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_securesession_enable_remote_endpoint(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_securesession_forward_stats(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_securesession_is_connected(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_securesession_listen(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_securesession_send(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_securesession_set_keepalive(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_securesession_set_retry_policy(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_securesession_set_tunnel_keepalive(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_securesession_set_tunnel_port(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_securesession_start_local_forward(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_securesession_start_remote_forward(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_securesession_start_udp_forward(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_securesession_stats(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_securesession_stop_local_forward(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_securesession_stop_remote_forward(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_securesession_stop_udp_forward(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_truststore_entries(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_truststore_level_of(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_truststore_remove(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_truststore_to_json(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_truststore_trust_device(void
    
);
int16_t uniffi_luciola_uniffi_checksum_constructor_discoverysession_new(void
    
);
int16_t uniffi_luciola_uniffi_checksum_constructor_securesession_new(void
    
);
int16_t uniffi_luciola_uniffi_checksum_constructor_truststore_new(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_onpeerdiscovered_on_peer_discovered(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_onpeerdiscovered_on_peer_updated(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_onpeerdiscovered_on_peer_lost(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_onpeerdiscovered_on_error(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_securesessionlistener_on_state(void
    
);
int16_t uniffi_luciola_uniffi_checksum_method_securesessionlistener_on_message(void
    
);
int32_t ffi_luciola_uniffi_uniffi_contract_version(void
    
);