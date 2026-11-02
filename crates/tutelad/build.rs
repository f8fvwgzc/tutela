//! Compiles the `tutela.authz.v1` protos. `protox` is a compiler written in
//! Rust, so a build needs no `protoc` on the machine.

use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let root = "../tutela-contracts/proto";
    let proto = "tutela/authz/v1/authz.proto";
    println!("cargo:rerun-if-changed={root}/{proto}");
    let descriptors = protox::compile([proto], [root])?;
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_fds(descriptors)?;
    Ok(())
}
