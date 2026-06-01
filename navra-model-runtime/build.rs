fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "openshell")]
    {
        tonic_build::compile_protos("proto/openshell_compute.proto")?;
    }
    Ok(())
}
