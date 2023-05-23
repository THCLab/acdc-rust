use cesrox::primitives::{codes::serial_number::SerialNumberCode, CesrPrimitive};
use uuid::Uuid;

pub struct Salt {
    uuid: Uuid,
}

pub fn new_uuid() -> String {
    let uuid = uuid::Uuid::new_v4();
    let salt = Salt { uuid };
    salt.to_str()
}

impl CesrPrimitive for Salt {
    fn derivative(&self) -> Vec<u8> {
        self.uuid.as_bytes().to_vec()
    }

    fn derivation_code(&self) -> cesrox::primitives::codes::PrimitiveCode {
        cesrox::primitives::codes::PrimitiveCode::SerialNumber(SerialNumberCode)
    }
}
