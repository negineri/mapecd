use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "mapecd", about = "MAP-E configuration daemon")]
pub struct Cli {
    /// 設定ファイルのパス
    #[arg(long, default_value = "/etc/mapecd/config.toml", global = true)]
    pub config: PathBuf,

    /// ログレベル (trace/debug/info/warn/error)
    #[arg(long, default_value = "info", global = true)]
    pub log_level: String,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// デーモンを起動する
    Start,
    /// デーモンの状態を表示する
    Status,
    /// デーモンを停止する
    Stop,
}
