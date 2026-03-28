use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::MapEError;

/// DHCPv6 受信モード。
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DhcpV6Mode {
    /// AF_PACKET パッシブキャプチャモード（デフォルト）。
    /// systemd-networkd 等の既存 DHCPv6 クライアントと競合しない。
    #[default]
    Capture,
    /// 独立 DHCPv6 クライアントモード。
    /// 他の DHCPv6 クライアントが動作していない場合に使用する。
    Client,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub upstream_interface: String,
    pub tunnel_interface: String,
    #[serde(default)]
    pub tunnel_mtu: Option<u32>,
    #[serde(default = "default_pid_file")]
    pub pid_file: PathBuf,
    #[serde(default = "default_map_rules_cache_file")]
    pub map_rules_cache_file: PathBuf,
    #[serde(default = "default_duid_file")]
    pub duid_file: PathBuf,
    /// DHCPv6 受信モード（デフォルト: capture）
    #[serde(default)]
    pub dhcpv6_mode: DhcpV6Mode,
    /// v6プラス向け静的 MAP ルールを使用するか（デフォルト: false）。
    ///
    /// true の場合、起動時から静的ルール集合のみを pending_map_rules に設定し、
    /// DHCPv6 Option 94 由来のルール受信・キャッシュ保存をスキップする。
    /// false の場合は既存動作（キャッシュ優先 + DHCPv6 更新）を維持する。
    ///
    /// 注意: 環境変数上書きは未対応。既存フィールドに環境変数対応がないため本フィールドも同様。
    #[serde(default)]
    pub use_v6plus_static_rules: bool,
}

fn default_pid_file() -> PathBuf {
    PathBuf::from("/run/mapecd.pid")
}

fn default_map_rules_cache_file() -> PathBuf {
    PathBuf::from("/run/mapecd/rules.cache")
}

fn default_duid_file() -> PathBuf {
    PathBuf::from("/var/lib/mapecd/duid")
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, MapEError> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                MapEError::ConfigNotFound {
                    path: path.to_path_buf(),
                }
            } else {
                MapEError::InvalidConfig(e.to_string())
            }
        })?;
        let config: Config =
            toml::from_str(&content).map_err(|e| MapEError::InvalidConfig(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), MapEError> {
        validate_interface_name(&self.upstream_interface)?;
        validate_interface_name(&self.tunnel_interface)?;

        if self.upstream_interface == self.tunnel_interface {
            return Err(MapEError::InvalidConfig(
                "upstream_interface and tunnel_interface must be different".to_string(),
            ));
        }

        if let Some(mtu) = self.tunnel_mtu {
            if mtu < 1280 || mtu > 65535 {
                return Err(MapEError::InvalidConfig(format!(
                    "tunnel_mtu must be between 1280 and 65535, got {mtu}"
                )));
            }
        }

        Ok(())
    }
}

fn validate_interface_name(name: &str) -> Result<(), MapEError> {
    if name.is_empty() {
        return Err(MapEError::InvalidConfig(
            "interface name must not be empty".to_string(),
        ));
    }
    if name.len() > 15 {
        return Err(MapEError::InvalidConfig(format!(
            "interface name '{name}' exceeds 15 characters (IFNAMSIZ-1)"
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(MapEError::InvalidConfig(format!(
            "interface name '{name}' contains invalid characters (allowed: alphanumeric, -, _, .)"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(toml: &str) -> Result<Config, MapEError> {
        let config: Config =
            toml::from_str(toml).map_err(|e| MapEError::InvalidConfig(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    // --- デシリアライズ基本 ---

    #[test]
    fn test_deserialize_minimal() {
        let cfg = parse(
            r#"
            upstream_interface = "eth0"
            tunnel_interface = "ip6tnl0"
        "#,
        )
        .unwrap();
        assert_eq!(cfg.upstream_interface, "eth0");
        assert_eq!(cfg.tunnel_interface, "ip6tnl0");
        assert_eq!(cfg.tunnel_mtu, None);
        assert_eq!(
            cfg.map_rules_cache_file,
            PathBuf::from("/run/mapecd/rules.cache")
        );
        assert_eq!(cfg.duid_file, PathBuf::from("/var/lib/mapecd/duid"));
        assert_eq!(cfg.dhcpv6_mode, DhcpV6Mode::Capture);
    }

    #[test]
    fn test_deserialize_with_tunnel_mtu() {
        let cfg = parse(
            r#"
            upstream_interface = "eth0"
            tunnel_interface = "ip6tnl0"
            tunnel_mtu = 1500
        "#,
        )
        .unwrap();
        assert_eq!(cfg.tunnel_mtu, Some(1500));
    }

    #[test]
    fn test_deserialize_custom_paths() {
        let cfg = parse(
            r#"
            upstream_interface = "eth0"
            tunnel_interface = "ip6tnl0"
            map_rules_cache_file = "/tmp/rules.cache"
            duid_file = "/tmp/duid"
        "#,
        )
        .unwrap();
        assert_eq!(cfg.map_rules_cache_file, PathBuf::from("/tmp/rules.cache"));
        assert_eq!(cfg.duid_file, PathBuf::from("/tmp/duid"));
    }

    // --- 必須フィールド欠落 ---

    #[test]
    fn test_missing_upstream_interface() {
        let result = parse(
            r#"
            tunnel_interface = "ip6tnl0"
        "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_tunnel_interface() {
        let result = parse(
            r#"
            upstream_interface = "eth0"
        "#,
        );
        assert!(result.is_err());
    }

    // --- インターフェース名バリデーション ---

    #[test]
    fn test_empty_upstream_interface() {
        let result = parse(
            r#"
            upstream_interface = ""
            tunnel_interface = "ip6tnl0"
        "#,
        );
        assert!(matches!(result, Err(MapEError::InvalidConfig(_))));
    }

    #[test]
    fn test_interface_name_too_long() {
        let result = parse(
            r#"
            upstream_interface = "eth0123456789012"
            tunnel_interface = "ip6tnl0"
        "#,
        );
        assert!(matches!(result, Err(MapEError::InvalidConfig(msg)) if msg.contains("exceeds 15 characters")));
    }

    #[test]
    fn test_interface_name_exactly_15_chars() {
        let cfg = parse(
            r#"
            upstream_interface = "eth012345678901"
            tunnel_interface = "ip6tnl0"
        "#,
        )
        .unwrap();
        assert_eq!(cfg.upstream_interface.len(), 15);
    }

    #[test]
    fn test_interface_name_invalid_chars() {
        let cases = [
            "eth 0",
            "eth;0",
            "eth\\0",
            "eth\"0",
            "eth'0",
            "eth/0",
            "eth\x000",
        ];
        for name in cases {
            let toml = format!(
                r#"upstream_interface = "{name}" tunnel_interface = "ip6tnl0""#
            );
            let result = parse(&toml);
            assert!(
                matches!(result, Err(MapEError::InvalidConfig(_))),
                "expected error for interface name: {name:?}"
            );
        }
    }

    #[test]
    fn test_interface_name_valid_chars() {
        let cfg = parse(
            r#"
            upstream_interface = "eth0.100-_x"
            tunnel_interface = "ip6tnl0"
        "#,
        )
        .unwrap();
        assert_eq!(cfg.upstream_interface, "eth0.100-_x");
    }

    #[test]
    fn test_same_interface_names() {
        let result = parse(
            r#"
            upstream_interface = "eth0"
            tunnel_interface = "eth0"
        "#,
        );
        assert!(
            matches!(result, Err(MapEError::InvalidConfig(msg)) if msg.contains("must be different"))
        );
    }

    // --- tunnel_mtu バリデーション ---

    #[test]
    fn test_tunnel_mtu_minimum_valid() {
        let cfg = parse(
            r#"
            upstream_interface = "eth0"
            tunnel_interface = "ip6tnl0"
            tunnel_mtu = 1280
        "#,
        )
        .unwrap();
        assert_eq!(cfg.tunnel_mtu, Some(1280));
    }

    #[test]
    fn test_tunnel_mtu_below_minimum() {
        let result = parse(
            r#"
            upstream_interface = "eth0"
            tunnel_interface = "ip6tnl0"
            tunnel_mtu = 1279
        "#,
        );
        assert!(
            matches!(result, Err(MapEError::InvalidConfig(msg)) if msg.contains("1280"))
        );
    }

    #[test]
    fn test_tunnel_mtu_maximum_valid() {
        let cfg = parse(
            r#"
            upstream_interface = "eth0"
            tunnel_interface = "ip6tnl0"
            tunnel_mtu = 65535
        "#,
        )
        .unwrap();
        assert_eq!(cfg.tunnel_mtu, Some(65535));
    }

    #[test]
    fn test_tunnel_mtu_above_maximum() {
        let result = parse(
            r#"
            upstream_interface = "eth0"
            tunnel_interface = "ip6tnl0"
            tunnel_mtu = 65536
        "#,
        );
        assert!(matches!(result, Err(MapEError::InvalidConfig(_))));
    }

    #[test]
    fn test_tunnel_mtu_zero() {
        let result = parse(
            r#"
            upstream_interface = "eth0"
            tunnel_interface = "ip6tnl0"
            tunnel_mtu = 0
        "#,
        );
        assert!(matches!(result, Err(MapEError::InvalidConfig(_))));
    }

    // --- dhcpv6_mode ---

    #[test]
    fn test_dhcpv6_mode_default_is_capture() {
        let cfg = parse(
            r#"
            upstream_interface = "eth0"
            tunnel_interface = "ip6tnl0"
        "#,
        )
        .unwrap();
        assert_eq!(cfg.dhcpv6_mode, DhcpV6Mode::Capture);
    }

    #[test]
    fn test_dhcpv6_mode_client() {
        let cfg = parse(
            r#"
            upstream_interface = "eth0"
            tunnel_interface = "ip6tnl0"
            dhcpv6_mode = "client"
        "#,
        )
        .unwrap();
        assert_eq!(cfg.dhcpv6_mode, DhcpV6Mode::Client);
    }

    // --- use_v6plus_static_rules ---

    #[test]
    fn test_use_v6plus_static_rules_default_false() {
        let cfg = parse(
            r#"
            upstream_interface = "eth0"
            tunnel_interface = "ip6tnl0"
        "#,
        )
        .unwrap();
        assert!(!cfg.use_v6plus_static_rules);
    }

    #[test]
    fn test_use_v6plus_static_rules_true() {
        let cfg = parse(
            r#"
            upstream_interface = "eth0"
            tunnel_interface = "ip6tnl0"
            use_v6plus_static_rules = true
        "#,
        )
        .unwrap();
        assert!(cfg.use_v6plus_static_rules);
    }
}
