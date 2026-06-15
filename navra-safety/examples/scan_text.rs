use navra_safety::{
    build_pipeline, FilterAction, FilterContext, FilterPipeline, PiiFilter, SecretFilter,
};

fn main() {
    let mut pipeline = FilterPipeline::new(FilterAction::Redact);
    pipeline.add_filter(SecretFilter::new());
    pipeline.add_filter(PiiFilter::new());

    let ctx = FilterContext {
        agent_name: "scan-example",
        operation: "read",
        path: None,
    };

    let inputs = [
        "Normal text with no sensitive data.",
        "AWS key: AKIAIOSFODNN7EXAMPLE",
        "SSN: 123-45-6789, email: alice@example.com",
        "Card: 4111111111111111",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK...",
        "File at /home/jean.dupont/documents/report.txt",
    ];

    for input in &inputs {
        match pipeline.process(input, &ctx) {
            Ok(output) => println!("OK:  {output}"),
            Err(reason) => println!("ERR: {reason}"),
        }
    }

    println!("\n--- Using 'standard' profile ---");
    let standard = build_pipeline("standard");
    let result = standard.process("Contact john@corp.com, SSN 123-45-6789", &ctx);
    println!("{}", result.unwrap());
}
