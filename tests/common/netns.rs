#![cfg(target_os = "linux")]

use std::os::fd::FromRawFd;
use std::os::unix::io::OwnedFd;

use nix::fcntl::{OFlag, open};
use nix::sched::{CloneFlags, setns};
use nix::sys::stat::Mode;

/// テスト用 Network Namespace。
///
/// `create()` で新しい名前付き Network Namespace を作成し、
/// `Drop` 時に `ip netns del <name>` で削除する。
pub struct TestNetNs {
    name: String,
}

#[allow(dead_code)]
impl TestNetNs {
    /// 新しいランダム名の Network Namespace を作成する。
    pub fn create() -> anyhow::Result<Self> {
        let name = format!("mapecd-test-{}", uuid::Uuid::new_v4().simple());
        let status = std::process::Command::new("ip")
            .args(["netns", "add", &name])
            .status()?;
        if !status.success() {
            anyhow::bail!("ip netns add {} failed: {:?}", name, status);
        }
        Ok(Self { name })
    }

    /// Namespace 内で非同期クロージャを実行する。
    ///
    /// `current_thread` ランタイム専用（スレッドをまたがない）。
    /// 実行後は元の Namespace に戻る。
    pub async fn run<F, Fut, T>(&self, f: F) -> anyhow::Result<T>
    where
        F: FnOnce(rtnetlink::Handle) -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<T>>,
    {
        // 現在の Namespace の fd を保存する
        let orig_raw = open("/proc/self/ns/net", OFlag::O_RDONLY, Mode::empty())?;
        // SAFETY: nix::fcntl::open が成功した場合、fd は有効な所有権付き fd である
        let orig_owned: OwnedFd = unsafe { OwnedFd::from_raw_fd(orig_raw) };

        // テスト用 Namespace に切り替える
        let ns_path = format!("/var/run/netns/{}", self.name);
        let ns_raw = open(ns_path.as_str(), OFlag::O_RDONLY, Mode::empty())?;
        // SAFETY: nix::fcntl::open が成功した場合、fd は有効な所有権付き fd である
        let ns_owned: OwnedFd = unsafe { OwnedFd::from_raw_fd(ns_raw) };
        setns(&ns_owned, CloneFlags::CLONE_NEWNET)?;

        // rtnetlink コネクションを作成する（Namespace 切り替え後に作成する必要がある）
        let (connection, handle, _) = rtnetlink::new_connection()?;
        let task = tokio::spawn(connection);

        // クロージャを実行する
        let result = f(handle).await;

        // タスクを終了させる
        task.abort();

        // 元の Namespace に戻す
        setns(&orig_owned, CloneFlags::CLONE_NEWNET)?;

        result
    }

    /// lo インターフェースを UP 状態にする。
    pub async fn bring_up_lo(&self) -> anyhow::Result<()> {
        self.run(|handle| async move {
            use futures::TryStreamExt;

            // lo の ifindex を取得する
            let mut links = handle.link().get().match_name("lo".to_string()).execute();
            let lo = links
                .try_next()
                .await?
                .ok_or_else(|| anyhow::anyhow!("lo not found"))?;
            let lo_index = lo.header.index;

            // UP にする
            handle.link().set(lo_index).up().execute().await?;
            Ok(())
        })
        .await
    }
}

impl Drop for TestNetNs {
    fn drop(&mut self) {
        let _ = std::process::Command::new("ip")
            .args(["netns", "del", &self.name])
            .status();
    }
}
