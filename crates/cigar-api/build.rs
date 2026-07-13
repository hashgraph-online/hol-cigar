//! Compiles the frozen v1 gRPC service contract for the Rust transport adapter.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let service_proto = "proto/cigar_service.proto";
    let proto_root = "proto";
    println!("cargo:rerun-if-changed={service_proto}");
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&[service_proto], &[proto_root])?;
    Ok(())
}
