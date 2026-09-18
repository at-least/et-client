//! Regenerates `crates/et-proto/src/gen/et.rs` from the upstream `proto/`
//! files. Run manually when `proto/` changes; the generated output is
//! committed and the workspace builds without this tool or protoc
//! (conch rule: generators are never a build dependency).
//!
//! ```sh
//! cargo run -p et-proto-gen   # protoc must be on PATH
//! ```

fn main() {
    buffa_build::Config::new()
        .files(&["proto/ET.proto", "proto/ETerminal.proto"])
        .includes(&["proto/"])
        .out_dir("crates/et-proto/src/gen")
        .generate_views(false)
        .generate_json(false)
        .file_per_package(true)
        .compile()
        .expect("proto generation failed (is protoc on PATH?)");
}
