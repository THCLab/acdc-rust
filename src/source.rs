use serde::{Deserialize, Serialize};

use crate::{identifier::Identifier, AttestationId};
#[derive(Serialize, Deserialize, Clone)]
pub enum Source {
    External(ExternalSource),
    Internal(AttestationId),
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExternalSource {
    testator_id: Identifier,
    attestation_id: AttestationId,
}

impl ExternalSource {
    pub fn new(testator_id: Identifier, attestation_id: AttestationId) -> Self {
        Self {
            testator_id,
            attestation_id,
        }
    }
}
