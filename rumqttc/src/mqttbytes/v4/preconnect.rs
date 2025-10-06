use crate::{mqttbytes::write_remaining_length, v4::len_len, Error, FixedHeader};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use core::fmt;

/// Pre-connection MQTT-MTD packet exclusively for MQTT-MTD
#[derive(Clone, PartialEq, Eq)]
pub struct PreConnect {
    pub payload_type: PayloadType,
    pub payload: Bytes,
}

/// Type of Preconnect Payload
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd)]
pub enum PayloadType {
    ClientHello = 0b00,
    ServerHello = 0b10,
    ServerAuth = 0b11,
}

/// Maps a number to Payload Type
pub fn payload_type(num: u8) -> Result<PayloadType, Error> {
    match num {
        0b00 => Ok(PayloadType::ClientHello),
        0b10 => Ok(PayloadType::ServerHello),
        0b11 => Ok(PayloadType::ServerAuth),
        payload_type => Err(Error::InvalidPreconnectPayloadType(payload_type)),
    }
}

impl PreConnect {
    pub fn new(payload_type: PayloadType, payload: Bytes) -> PreConnect {
        PreConnect {
            payload_type,
            payload,
        }
    }

    pub fn len(&self) -> usize {
        self.payload.len()
    }

    pub fn size(&self) -> usize {
        let len = self.len();
        let remaining_len_size = len_len(len);

        1 + remaining_len_size + len
    }

    pub fn read(fixed_header: FixedHeader, mut bytes: Bytes) -> Result<Self, Error> {
        let payload_type = payload_type(fixed_header.byte1 & 0xF)?;

        let variable_header_index = fixed_header.fixed_header_len;
        bytes.advance(variable_header_index);

        let publish = PreConnect {
            payload_type,
            payload: bytes,
        };

        Ok(publish)
    }

    pub fn write(&self, buffer: &mut BytesMut) -> Result<usize, Error> {
        let len = self.len();

        buffer.put_u8(0b1111_0000 | self.payload_type as u8);

        let count = write_remaining_length(buffer, len)?;

        buffer.extend_from_slice(&self.payload);

        Ok(1 + count + len)
    }
}

impl fmt::Debug for PreConnect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PayloadType = {}, Payload Size = {}",
            self.payload_type as u8,
            self.payload.len()
        )
    }
}
