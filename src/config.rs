use serde::Deserialize;

/// アプリケーション設定
#[derive(Debug, Deserialize)]
pub struct AppConfig {
    /// MAP-E ルール設定（ISP から取得できない場合の手動設定）
    pub map_rule: Option<MapRuleConfig>,
    /// ログレベル（RUST_LOG 環境変数で上書き可能）
    pub log_level: Option<String>,
}

/// MAP-E BMR（Basic Mapping Rule）手動設定
#[derive(Debug, Deserialize)]
pub struct MapRuleConfig {
    /// ISP の IPv6 プレフィックス
    pub ipv6_prefix: String,
    /// MAP IPv4 プレフィックス
    pub ipv4_prefix: String,
    /// EA-bits 長
    pub ea_length: u8,
    /// PSID オフセット
    pub psid_offset: u8,
}

impl AppConfig {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let cfg = config::Config::builder()
            .add_source(config::File::with_name(path).required(false))
            .add_source(config::Environment::with_prefix("MAPECD"))
            .build()?;

        Ok(cfg.try_deserialize()?)
    }
}
