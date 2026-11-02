//! Compiles the `tutela.authz.v1` and `tutela.admin.v1` protos. `protox` is
//! a compiler written in Rust, so a build needs no `protoc` on the machine.

use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let root = "../tutela-contracts/proto";
    let protos = ["tutela/authz/v1/authz.proto", "tutela/admin/v1/admin.proto"];
    for proto in protos {
        println!("cargo:rerun-if-changed={root}/{proto}");
    }
    let descriptors = protox::compile(protos, [root])?;
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_fds(descriptors)?;
    Ok(())
}
