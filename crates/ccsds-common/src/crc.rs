//! CRC used by the Frame Error Control Field (FECF) of TM Transfer Frames.
//!
//! CCSDS 132.0-B-3, 4.1.6: generator polynomial x^16 + x^12 + x^5 + 1,
//! register preset to all ones, no final inversion
//! (also known as CRC-16/CCITT-FALSE).

/// Computes the CRC-16 over `data`.
pub fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xffff;
    for &byte in data {
        crc ^= u16::from(byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_check_value() {
        assert_eq!(crc16_ccitt(b"123456789"), 0x29b1);
    }

    #[test]
    fn empty_input_is_preset() {
        assert_eq!(crc16_ccitt(&[]), 0xffff);
    }
}
