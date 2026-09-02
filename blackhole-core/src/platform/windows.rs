//! Windows kill switch backend, implemented in user mode against the
//! Windows Filtering Platform (WFP) via Microsoft's official `windows-rs`
//! bindings.
//!
//! Design mirrors the Linux nftables backend: default-deny at the
//! `FWPM_LAYER_ALE_AUTH_CONNECT_V4`/`V6` layers (which fire once per
//! outbound connection attempt, so a single filter blocks/permits an entire
//! TCP or UDP flow rather than needing per-packet state tracking), with
//! explicit permit filters for loopback and for this process's own
//! executable (since `arti` runs in-process rather than as a separate
//! system daemon with its own interface).
//!
//! # Future kernel-mode evolution
//!
//! This backend only calls the user-mode `Fwpm*` APIs. A user-mode engine
//! session can still be torn down if the process that opened it is killed
//! forcefully in some configurations, and user-mode filters are easier for
//! another privileged process to remove than a kernel callout driver's own
//! filters. A signed WFP callout driver (built with `windows-drivers-rs`)
//! is the natural next step for stronger tamper-resistance, and it can be
//! dropped in behind the same [`NetworkGuard`] trait without changing this
//! module's public shape. Developing that driver requires enabling test
//! signing (`bcdedit /set testsigning on`) on the development machine;
//! distributing it beyond personal use requires an EV code-signing
//! certificate for kernel driver submission/attestation signing.
//!
//! # Known limitations (v1)
//!
//! - IPv6 loopback (`::1`) is not separately allow-listed; only this
//!   process's executable is permitted on the V6 layer. Extend
//!   `enable_v6_filters` with a `FWPM_CONDITION_IP_REMOTE_ADDRESS` /
//!   `byteArray16` condition if that turns out to matter for your setup.
//! - Filter/session persistence semantics (whether rules survive this
//!   process exiting or the machine sleeping) should be validated with
//!   `netsh wfp show filters` before relying on this for anything beyond
//!   personal use; this implementation requests `FWPM_FILTER_FLAG_PERSISTENT`
//!   but does not yet use WFP's boot-time filter class.

use std::ffi::c_void;
use std::sync::Arc;

use async_trait::async_trait;
use tracing::{info, warn};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows::core::{GUID, HSTRING, PCWSTR, PWSTR, w};

use crate::error::BlackholeError;
use crate::guard::{GuardStateMachine, GuardStatus, NetworkGuard};
use crate::tor::{PermitTarget, TorBackend};

// Fixed GUIDs unique to blackhole-core, generated once and hardcoded so
// `enable`/`disable`/`status` always refer to the same WFP objects across
// process restarts.
const PROVIDER_KEY: GUID = GUID::from_u128(0xd156256c_836d_468f_b6ad_f3491461112d);
const SUBLAYER_KEY: GUID = GUID::from_u128(0xc969c867_67e9_4728_9a1d_7e8ef90892cb);
const FILTER_BLOCK_V4: GUID = GUID::from_u128(0xe0430b29_ad40_4ee3_993c_ec7b03cc657f);
const FILTER_BLOCK_V6: GUID = GUID::from_u128(0xba35bb07_2608_45cb_990a_28ffea5a3071);
const FILTER_LOOPBACK_V4: GUID = GUID::from_u128(0x42728508_68cb_4c4a_959a_8633d8eca293);
const FILTER_APP_V4: GUID = GUID::from_u128(0xcb0969c1_5bb7_4954_b519_971e6eb62c63);
const FILTER_APP_V6: GUID = GUID::from_u128(0x90659bcd_2a2a_4e40_9403_9091dcd6c4cf);

// WFP's `providerKey` struct field is `*mut GUID`: the API reads through
// that pointer whenever it likes during a synchronous `Fwpm*Add0` call, so
// the pointee must stay alive for that call. A local `let mut provider_key
// = PROVIDER_KEY` inside a helper that *returns* the filter/sublayer struct
// (rather than calling the FFI itself) doesn't satisfy that: the local is
// dropped when the helper returns, before the caller's later `Fwpm*Add0`
// call dereferences the now-dangling pointer. A `static` (not `const`) has
// one fixed address for the life of the process, so pointing at it instead
// is always sound — nothing ever writes through this pointer.
static PROVIDER_KEY_STATIC: GUID = PROVIDER_KEY;

/// All filter keys this backend ever creates, in the order they should be
/// deleted (order doesn't matter for filters, only that they're all gone
/// before the sublayer is deleted).
const ALL_FILTER_KEYS: [GUID; 4] = [
    FILTER_BLOCK_V4,
    FILTER_BLOCK_V6,
    FILTER_LOOPBACK_V4,
    FILTER_APP_V4,
];

pub struct WindowsGuard {
    state: GuardStateMachine,
    tor: Arc<dyn TorBackend>,
}

impl WindowsGuard {
    /// Takes a shared `Arc<dyn TorBackend>` (rather than owning it
    /// outright) so callers can keep their own handle for Tor-specific
    /// queries (bootstrap detail, exit IP — arti-backend-specific, see
    /// `TorOrchestrator`) alongside the guard. Unlike the Linux backend,
    /// *this* one does need to know which backend it's holding: the WFP
    /// permit rule is scoped to a single executable, and which executable
    /// that should be depends on `tor.permit_target()` — this process
    /// itself for the in-process `arti` backend, or the child `tor.exe`'s
    /// own path for the subprocess backend.
    pub fn new(tor: Arc<dyn TorBackend>) -> Self {
        Self {
            state: GuardStateMachine::new(),
            tor,
        }
    }

    fn open_engine() -> Result<HANDLE, BlackholeError> {
        let mut handle = HANDLE::default();
        // SAFETY: all pointer arguments are either null (server name =
        // local machine, no custom auth identity/session) or point to a
        // valid, correctly-sized `HANDLE` we just created.
        let status =
            unsafe { FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, None, &mut handle) };
        if status != 0 {
            return Err(BlackholeError::Platform(format!(
                "FwpmEngineOpen0 failed (0x{status:08x})"
            )));
        }
        Ok(handle)
    }

    fn close_engine(handle: HANDLE) {
        // SAFETY: `handle` came from a successful `FwpmEngineOpen0` call.
        let status = unsafe { FwpmEngineClose0(handle) };
        if status != 0 {
            warn!("FwpmEngineClose0 failed (0x{status:08x})");
        }
    }

    /// Run `f` with an open WFP engine handle on a blocking thread (the
    /// `Fwpm*` calls are synchronous syscalls), closing the handle
    /// afterwards regardless of outcome.
    async fn with_engine<F, T>(f: F) -> Result<T, BlackholeError>
    where
        F: FnOnce(HANDLE) -> Result<T, BlackholeError> + Send + 'static,
        T: Send + 'static,
    {
        tokio::task::spawn_blocking(move || {
            let handle = Self::open_engine()?;
            let result = f(handle);
            Self::close_engine(handle);
            result
        })
        .await
        .map_err(|e| BlackholeError::Platform(format!("WFP worker task panicked: {e}")))?
    }

    /// Pointer to the one process-static provider key GUID, valid for the
    /// life of the process — see the comment on `PROVIDER_KEY_STATIC`.
    fn provider_key_ptr() -> *mut GUID {
        std::ptr::addr_of!(PROVIDER_KEY_STATIC) as *mut GUID
    }

    fn display(name: PCWSTR, description: PCWSTR) -> FWPM_DISPLAY_DATA0 {
        FWPM_DISPLAY_DATA0 {
            // WFP only reads these strings when the object is added; the
            // API takes `PWSTR` for both add and query, but never mutates
            // them on add, so pointing at `'static` literals is sound.
            name: PWSTR(name.as_ptr() as *mut u16),
            description: PWSTR(description.as_ptr() as *mut u16),
        }
    }

    fn sublayer_exists(engine: HANDLE) -> bool {
        let mut out: *mut FWPM_SUBLAYER0 = std::ptr::null_mut();
        // SAFETY: `engine` is a valid handle; `out` is a valid out-pointer.
        let status = unsafe { FwpmSubLayerGetByKey0(engine, &SUBLAYER_KEY, &mut out) };
        if status == 0 {
            // SAFETY: `out` was allocated by FwpmSubLayerGetByKey0 on success.
            unsafe { FwpmFreeMemory0(&mut out as *mut _ as *mut *mut c_void) };
            true
        } else {
            false
        }
    }

    fn delete_all_our_objects(engine: HANDLE) {
        for key in ALL_FILTER_KEYS {
            // SAFETY: `engine` valid; `key` is one of our own constants.
            // Errors (including "not found") are intentionally ignored
            // here: this is the "clean slate" pass before re-adding, run
            // both on enable() and on disable().
            unsafe {
                let _ = FwpmFilterDeleteByKey0(engine, &key);
            }
        }
        // SAFETY: `engine` valid; sublayer deletion only succeeds once no
        // filter still references it, which is true after the loop above.
        unsafe {
            let _ = FwpmSubLayerDeleteByKey0(engine, &SUBLAYER_KEY);
        }
    }

    fn add_sublayer(engine: HANDLE) -> Result<(), BlackholeError> {
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: SUBLAYER_KEY,
            displayData: Self::display(
                w!("BlackHole Kill Switch"),
                w!("blackhole-core default-deny sublayer"),
            ),
            providerKey: Self::provider_key_ptr(),
            weight: 0x8000,
            ..Default::default()
        };

        // SAFETY: all pointers are valid for the duration of this call.
        let status = unsafe { FwpmSubLayerAdd0(engine, &sublayer, None) };
        if status != 0 {
            return Err(BlackholeError::Platform(format!(
                "FwpmSubLayerAdd0 failed (0x{status:08x})"
            )));
        }
        Ok(())
    }

    /// Build a zero-condition filter that blocks everything at `layer`,
    /// evaluated at the lowest weight so the permit filters (added with a
    /// higher weight) win first.
    fn block_all_filter(layer: GUID, key: GUID, name: PCWSTR) -> FWPM_FILTER0 {
        FWPM_FILTER0 {
            filterKey: key,
            displayData: Self::display(name, w!("blackhole-core default-deny")),
            flags: FWPM_FILTER_FLAG_PERSISTENT,
            providerKey: Self::provider_key_ptr(),
            layerKey: layer,
            subLayerKey: SUBLAYER_KEY,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 { uint8: 0 },
            },
            numFilterConditions: 0,
            filterCondition: std::ptr::null_mut(),
            action: FWPM_ACTION0 {
                r#type: FWP_ACTION_BLOCK,
                // SAFETY: zero is a valid bit pattern for this union; it is
                // only meaningful for callout actions, which this isn't.
                Anonymous: unsafe { std::mem::zeroed() },
            },
            ..Default::default()
        }
    }

    fn permit_loopback_v4_filter() -> (FWP_V4_ADDR_AND_MASK, FWPM_FILTER_CONDITION0) {
        let addr_mask = FWP_V4_ADDR_AND_MASK {
            addr: 0x7F000000, // 127.0.0.0
            mask: 0xFF000000, // /8
        };
        let condition = FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_V4_ADDR_MASK,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    // Filled in with a pointer to `addr_mask` by the caller
                    // once `addr_mask` has a stable address.
                    v4AddrMask: std::ptr::null_mut(),
                },
            },
        };
        (addr_mask, condition)
    }

    fn permit_app_filter(app_id: *mut FWP_BYTE_BLOB) -> FWPM_FILTER_CONDITION0 {
        FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_ALE_APP_ID,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_BYTE_BLOB_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: app_id },
            },
        }
    }

    fn permit_filter(
        layer: GUID,
        key: GUID,
        name: PCWSTR,
        conditions: &mut [FWPM_FILTER_CONDITION0],
    ) -> FWPM_FILTER0 {
        FWPM_FILTER0 {
            filterKey: key,
            displayData: Self::display(name, w!("blackhole-core allow-rule")),
            flags: FWPM_FILTER_FLAG_PERSISTENT,
            providerKey: Self::provider_key_ptr(),
            layerKey: layer,
            subLayerKey: SUBLAYER_KEY,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 { uint8: 15 },
            },
            numFilterConditions: conditions.len() as u32,
            filterCondition: conditions.as_mut_ptr(),
            action: FWPM_ACTION0 {
                r#type: FWP_ACTION_PERMIT,
                // SAFETY: see `block_all_filter`.
                Anonymous: unsafe { std::mem::zeroed() },
            },
            ..Default::default()
        }
    }

    fn add_filter(engine: HANDLE, filter: &FWPM_FILTER0) -> Result<(), BlackholeError> {
        // SAFETY: `engine` is valid; `filter` and everything it points to
        // (conditions, provider key) are valid for the duration of this
        // call, which is synchronous.
        let status = unsafe { FwpmFilterAdd0(engine, filter, None, None) };
        if status != 0 {
            return Err(BlackholeError::Platform(format!(
                "FwpmFilterAdd0 failed for filter {:?} (0x{status:08x})",
                filter.filterKey
            )));
        }
        Ok(())
    }

    fn get_app_id(exe_path: &std::path::Path) -> Result<*mut FWP_BYTE_BLOB, BlackholeError> {
        let wide = HSTRING::from(exe_path.to_string_lossy().as_ref());
        let mut app_id: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
        // SAFETY: `wide` is a valid, NUL-terminated wide string for the
        // duration of this call; `app_id` is a valid out-pointer.
        let status = unsafe { FwpmGetAppIdFromFileName0(&wide, &mut app_id) };
        if status != 0 {
            return Err(BlackholeError::Platform(format!(
                "FwpmGetAppIdFromFileName0 failed for {exe_path:?} (0x{status:08x})"
            )));
        }
        Ok(app_id)
    }

    fn apply_rules(engine: HANDLE, exe_path: std::path::PathBuf) -> Result<(), BlackholeError> {
        // Clean slate: never layer new rules on top of a previous run's.
        Self::delete_all_our_objects(engine);
        Self::add_sublayer(engine)?;

        Self::add_filter(
            engine,
            &Self::block_all_filter(
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                FILTER_BLOCK_V4,
                w!("BlackHole: deny all outbound IPv4"),
            ),
        )?;
        Self::add_filter(
            engine,
            &Self::block_all_filter(
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                FILTER_BLOCK_V6,
                w!("BlackHole: deny all outbound IPv6"),
            ),
        )?;

        let (addr_mask, mut loopback_condition) = Self::permit_loopback_v4_filter();
        loopback_condition.conditionValue.Anonymous.v4AddrMask =
            &addr_mask as *const _ as *mut FWP_V4_ADDR_AND_MASK;
        Self::add_filter(
            engine,
            &Self::permit_filter(
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                FILTER_LOOPBACK_V4,
                w!("BlackHole: allow loopback"),
                &mut [loopback_condition],
            ),
        )?;

        let app_id = Self::get_app_id(&exe_path)?;
        let free_app_id = || {
            // SAFETY: `app_id` was allocated by FwpmGetAppIdFromFileName0.
            unsafe { FwpmFreeMemory0(&mut (app_id as *mut c_void)) };
        };

        let mut app_condition_v4 = Self::permit_app_filter(app_id);
        let result_v4 = Self::add_filter(
            engine,
            &Self::permit_filter(
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                FILTER_APP_V4,
                w!("BlackHole: allow this process (IPv4)"),
                std::slice::from_mut(&mut app_condition_v4),
            ),
        );
        if let Err(e) = result_v4 {
            free_app_id();
            return Err(e);
        }

        let mut app_condition_v6 = Self::permit_app_filter(app_id);
        let result_v6 = Self::add_filter(
            engine,
            &Self::permit_filter(
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                FILTER_APP_V6,
                w!("BlackHole: allow this process (IPv6)"),
                std::slice::from_mut(&mut app_condition_v6),
            ),
        );
        free_app_id();
        result_v6
    }
}

impl WindowsGuard {
    /// The single executable path the WFP permit rule should scope to —
    /// this process's own path for the in-process `arti` backend, or the
    /// child `tor.exe`'s path for the subprocess backend. See the doc
    /// comment on `WindowsGuard::new`.
    fn permit_exe_path(&self) -> Result<std::path::PathBuf, BlackholeError> {
        match self.tor.permit_target() {
            PermitTarget::ThisProcess => std::env::current_exe().map_err(BlackholeError::from),
            PermitTarget::ChildProcess(path) => Ok(path),
        }
    }
}

#[async_trait]
impl NetworkGuard for WindowsGuard {
    async fn enable(&self) -> Result<(), BlackholeError> {
        self.state.begin_enable()?;

        let exe_path = self.permit_exe_path();
        let result = match exe_path {
            Ok(path) => Self::with_engine(move |engine| Self::apply_rules(engine, path)).await,
            Err(e) => Err(e),
        };

        self.state.finish_enable(result.is_ok());
        if result.is_ok() {
            info!("WFP kill switch enabled (default-deny outbound IPv4/IPv6)");
        } else {
            warn!(
                ?result,
                "failed to fully apply WFP kill switch; treating as faulted (fail-closed)"
            );
        }
        result
    }

    async fn disable(&self) -> Result<(), BlackholeError> {
        self.state.begin_disable()?;

        let result = Self::with_engine(|engine| {
            Self::delete_all_our_objects(engine);
            Ok(())
        })
        .await;

        self.state.finish_disable(result.is_ok());
        if result.is_ok() {
            info!("WFP kill switch disabled");
        }
        result
    }

    async fn status(&self) -> Result<GuardStatus, BlackholeError> {
        let actually_blocking = Self::with_engine(|engine| Ok(Self::sublayer_exists(engine)))
            .await
            .unwrap_or(false);
        let (state, detail) = self.state.reconcile(actually_blocking, "WFP sublayer");

        let tor = self.tor.status().await;
        Ok(GuardStatus {
            state,
            tor_bootstrap_percent: Some(tor.bootstrap_percent),
            allowed_egress: self.permit_exe_path().ok().map(|p| p.display().to_string()),
            detail: detail.or(tor.blocked_reason),
        })
    }

    async fn new_identity(&self) -> Result<(), BlackholeError> {
        self.state.require_enabled("new_identity")?;
        self.tor.new_identity().await
    }
}
