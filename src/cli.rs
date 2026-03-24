use anyhow::Result;
use clap::{Parser, Subcommand};

/// MAP-E クライアントデーモン
#[derive(Debug, Parser)]
#[command(name = "mapecd", version, about)]
pub struct Cli {
    /// 設定ファイルのパス
    #[arg(short, long, default_value = "/etc/mapecd/config.toml")]
    pub config: String,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// デーモンとして起動
    Start {
        /// ISP と接続する NIC 名
        #[arg(short, long)]
        interface: String,
    },
    /// 現在の MAP-E 設定を表示
    Status,
    /// ネットワーク設定を削除してクリーンアップ
    Stop,
}

impl Cli {
    pub async fn run(&self) -> Result<()> {
        match &self.command {
            Some(Command::Start { interface }) => {
                tracing::info!("MAP-E クライアントを起動します (interface: {})", interface);
                // TODO: メインループ実装
                Ok(())
            }
            Some(Command::Status) => {
                tracing::info!("MAP-E 設定を表示します");
                // TODO: 状態表示実装
                Ok(())
            }
            Some(Command::Stop) => {
                tracing::info!("MAP-E 設定をクリーンアップします");
                // TODO: クリーンアップ実装
                Ok(())
            }
            None => {
                tracing::error!("サブコマンドを指定してください。--help を参照してください。");
                Ok(())
            }
        }
    }
}
