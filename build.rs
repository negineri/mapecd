fn main() {
    #[cfg(target_os = "linux")]
    {
        use aya_build::{Package, Toolchain, build_ebpf};
        build_ebpf(
            [Package { name: "mapecd-ebpf", root_dir: "mapecd-ebpf", ..Default::default() }],
            Toolchain::Custom("nightly-2026-03-27"),
        )
        .unwrap();
    }
}
