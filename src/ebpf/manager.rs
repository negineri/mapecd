//! eBPF プログラムのロード・TC リンク・CONFIG_MAP 更新を管理する。
//!
//! # 責務
//!
//! - BPF ELF ロード（`aya::Ebpf::load`）
//! - clsact qdisc セットアップと TC プログラムのアタッチ
//! - CONFIG_MAP の初期化・更新
//! - リンク解除（`unlink_tc()` で link_id を detach）

use aya::{
    Ebpf, Pod,
    maps::Array,
    programs::{SchedClassifier, TcAttachType, tc::SchedClassifierLinkId},
};
use mapecd_common::PsidConfig;

use crate::{
    error::MapEError,
    map::rule::{MapeParams, PortParams},
};

// ────────────────────────────────────────────────────────────
// Pod ラッパー
// ────────────────────────────────────────────────────────────

/// `PsidConfig` の Pod ラッパー。
///
/// `aya::Pod` は crate 外の型に直接実装できないため（orphan rule）、
/// `#[repr(transparent)]` ラッパーに実装して Array 操作に使用する。
#[repr(transparent)]
#[derive(Clone, Copy)]
struct PsidConfigPod(PsidConfig);

// SAFETY: PsidConfig は #[repr(C)] で全フィールドが整数型のみ。
// 任意のバイトパターンで有効な値を構成できる。
unsafe impl Pod for PsidConfigPod {}

// ────────────────────────────────────────────────────────────
// EbpfHandle トレイト（テスト用 Mock 差し替えのため定義）
// ────────────────────────────────────────────────────────────

/// eBPF 操作を抽象化するトレイト。
///
/// `EbpfManager` に実装し、`lifecycle.rs` のテストでは `MockEbpfHandle` に差し替える。
pub trait EbpfHandle: Send {
    fn load(
        params: &PsidConfig,
    ) -> impl std::future::Future<Output = Result<Self, MapEError>> + Send
    where
        Self: Sized;

    fn link_tc(
        &mut self,
        interface: &str,
    ) -> impl std::future::Future<Output = Result<(), MapEError>> + Send;

    fn update_config(
        &mut self,
        params: &PsidConfig,
    ) -> impl std::future::Future<Output = Result<(), MapEError>> + Send;

    fn unlink_tc(&mut self) -> impl std::future::Future<Output = Result<(), MapEError>> + Send;
}

// ────────────────────────────────────────────────────────────
// EbpfManager
// ────────────────────────────────────────────────────────────

/// BPF ELF のロード・TC リンク・CONFIG_MAP 更新を担う。
pub struct EbpfManager {
    ebpf: Ebpf,
    interface: Option<String>,
    /// egress フィルタの link_id（detach に使用）
    egress_link_id: Option<SchedClassifierLinkId>,
    /// ingress フィルタの link_id（detach に使用）
    ingress_link_id: Option<SchedClassifierLinkId>,
}

impl EbpfHandle for EbpfManager {
    async fn load(params: &PsidConfig) -> Result<Self, MapEError> {
        let bytes = aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/mapecd-ebpf-prog"
        ));
        let mut ebpf = Ebpf::load(bytes).map_err(|e| {
            MapEError::EbpfError(format!("failed to load BPF ELF: {e}"))
        })?;

        // CONFIG_MAP を初期化
        set_config_map(&mut ebpf, params)?;

        Ok(Self {
            ebpf,
            interface: None,
            egress_link_id: None,
            ingress_link_id: None,
        })
    }

    async fn link_tc(&mut self, interface: &str) -> Result<(), MapEError> {
        // clsact qdisc を追加（既存の場合はエラーを無視）
        let _ = aya::programs::tc::qdisc_add_clsact(interface);

        // egress プログラムをロード・アタッチ
        let egress: &mut SchedClassifier = self
            .ebpf
            .program_mut("tc_egress")
            .ok_or_else(|| MapEError::EbpfError("tc_egress program not found".to_string()))?
            .try_into()
            .map_err(|e| MapEError::EbpfError(format!("tc_egress program cast failed: {e}")))?;
        egress
            .load()
            .map_err(|e| MapEError::EbpfError(format!("tc_egress load failed: {e}")))?;
        let egress_link_id = egress
            .attach(interface, TcAttachType::Egress)
            .map_err(|e| MapEError::EbpfError(format!("tc_egress attach failed: {e}")))?;

        // ingress プログラムをロード・アタッチ
        let ingress: &mut SchedClassifier = self
            .ebpf
            .program_mut("tc_ingress")
            .ok_or_else(|| MapEError::EbpfError("tc_ingress program not found".to_string()))?
            .try_into()
            .map_err(|e| {
                MapEError::EbpfError(format!("tc_ingress program cast failed: {e}"))
            })?;
        ingress
            .load()
            .map_err(|e| MapEError::EbpfError(format!("tc_ingress load failed: {e}")))?;
        let ingress_link_id = ingress
            .attach(interface, TcAttachType::Ingress)
            .map_err(|e| MapEError::EbpfError(format!("tc_ingress attach failed: {e}")))?;

        self.interface = Some(interface.to_string());
        self.egress_link_id = Some(egress_link_id);
        self.ingress_link_id = Some(ingress_link_id);

        Ok(())
    }

    async fn update_config(&mut self, params: &PsidConfig) -> Result<(), MapEError> {
        set_config_map(&mut self.ebpf, params)
    }

    async fn unlink_tc(&mut self) -> Result<(), MapEError> {
        // egress フィルタを detach
        if let Some(link_id) = self.egress_link_id.take() {
            if let Ok(prog) = self
                .ebpf
                .program_mut("tc_egress")
                .ok_or(())
                .and_then(|p| TryInto::<&mut SchedClassifier>::try_into(p).map_err(|_| ()))
            {
                let _ = prog.detach(link_id);
            }
        }

        // ingress フィルタを detach
        if let Some(link_id) = self.ingress_link_id.take() {
            if let Ok(prog) = self
                .ebpf
                .program_mut("tc_ingress")
                .ok_or(())
                .and_then(|p| TryInto::<&mut SchedClassifier>::try_into(p).map_err(|_| ()))
            {
                let _ = prog.detach(link_id);
            }
        }

        self.interface = None;
        Ok(())
    }
}

// ────────────────────────────────────────────────────────────
// 内部ヘルパー
// ────────────────────────────────────────────────────────────

fn set_config_map(ebpf: &mut Ebpf, params: &PsidConfig) -> Result<(), MapEError> {
    let mut map: Array<_, PsidConfigPod> =
        Array::try_from(ebpf.map_mut("CONFIG_MAP").ok_or_else(|| {
            MapEError::EbpfError("CONFIG_MAP not found in BPF ELF".to_string())
        })?)
        .map_err(|e| MapEError::EbpfError(format!("CONFIG_MAP type error: {e}")))?;
    map.set(0, PsidConfigPod(*params), 0)
        .map_err(|e| MapEError::EbpfError(format!("CONFIG_MAP set failed: {e}")))?;
    Ok(())
}

// ────────────────────────────────────────────────────────────
// MapeParams → PsidConfig 変換
// ────────────────────────────────────────────────────────────

/// `MapeParams` から `PsidConfig` を生成する。
///
/// `mapecd-common` は `#![no_std]` のため `MapeParams` に依存できないため、
/// この変換はユーザースペース側（本ファイル）に実装する。
pub fn psid_config_from_params(params: &MapeParams) -> Result<PsidConfig, MapEError> {
    let PortParams { psid_offset, psid_length } = params.rule.port_params;
    PsidConfig::try_new(psid_offset, psid_length, params.psid).ok_or_else(|| {
        MapEError::EbpfError(format!(
            "invalid PSID params: offset={psid_offset} length={psid_length} (offset+length must be <= 16)"
        ))
    })
}
