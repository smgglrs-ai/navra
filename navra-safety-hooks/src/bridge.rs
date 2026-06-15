//! Bridges between standalone `navra-safety` types and navra workspace types.

use navra_model::{ClassifyRequest, ModelBackend};
use std::sync::Arc;

/// Convert standalone `Confidentiality` to the navra-protocol version.
pub fn to_protocol_confidentiality(
    c: navra_safety::Confidentiality,
) -> navra_protocol::label::Confidentiality {
    match c {
        navra_safety::Confidentiality::Public => navra_protocol::label::Confidentiality::Public,
        navra_safety::Confidentiality::Sensitive => {
            navra_protocol::label::Confidentiality::Sensitive
        }
        navra_safety::Confidentiality::Pii => navra_protocol::label::Confidentiality::Pii,
        navra_safety::Confidentiality::Secret => navra_protocol::label::Confidentiality::Secret,
    }
}

/// Convert navra-protocol `Confidentiality` to the standalone version.
pub fn from_protocol_confidentiality(
    c: navra_protocol::label::Confidentiality,
) -> navra_safety::Confidentiality {
    match c {
        navra_protocol::label::Confidentiality::Public => navra_safety::Confidentiality::Public,
        navra_protocol::label::Confidentiality::Sensitive => {
            navra_safety::Confidentiality::Sensitive
        }
        navra_protocol::label::Confidentiality::Pii => navra_safety::Confidentiality::Pii,
        navra_protocol::label::Confidentiality::Secret => navra_safety::Confidentiality::Secret,
    }
}

/// Wraps a `navra_model::ModelBackend` as a `navra_safety::Classifier`.
pub struct ClassifierBridge {
    backend: Arc<dyn ModelBackend>,
}

impl ClassifierBridge {
    pub fn new(backend: Arc<dyn ModelBackend>) -> Self {
        Self { backend }
    }
}

impl navra_safety::Classifier for ClassifierBridge {
    fn classify<'a>(
        &'a self,
        text: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<navra_safety::ClassifyOutput, navra_safety::ClassifyError>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let request = ClassifyRequest {
                text: text.to_string(),
            };
            match self.backend.classify(&request).await {
                Ok(response) => Ok(navra_safety::ClassifyOutput {
                    labels: response
                        .labels
                        .into_iter()
                        .map(|l| navra_safety::ClassifyLabel {
                            label: l.label,
                            score: l.score,
                        })
                        .collect(),
                }),
                Err(e) => Err(navra_safety::ClassifyError::Inference(e.to_string())),
            }
        })
    }
}
