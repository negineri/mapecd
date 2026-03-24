use bytes::{Bytes, BytesMut};

use super::Dhcpv6Error;

/// DHCPv6 メッセージタイプ
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Solicit = 1,
    Advertise = 2,
    Request = 3,
    Reply = 7,
}

/// DHCPv6 オプションコード
pub mod option_code {
    pub const CLIENTID: u16 = 1;
    pub const SERVERID: u16 = 2;
    pub const ORO: u16 = 6;
    pub const ELAPSED_TIME: u16 = 8;
    /// OPTION_S46_CONT_MAPE (RFC 7598)
    pub const S46_CONT_MAPE: u16 = 95;
}

/// Solicit メッセージを構築する
pub fn build_solicit() -> Bytes {
    let mut buf = BytesMut::new();
    // TODO: 完全な Solicit パケット構築
    // - Message Type: 1 (Solicit)
    // - Transaction ID: ランダム 3 バイト
    // - Option: Client Identifier (DUID)
    // - Option: Elapsed Time
    // - Option: Option Request (ORO) → Option 95 を要求
    buf.freeze()
}

/// Request メッセージを構築する
pub fn build_request(server_id: &[u8], transaction_id: [u8; 3]) -> Bytes {
    let mut buf = BytesMut::new();
    // TODO: 完全な Request パケット構築
    buf.freeze()
}

/// Reply メッセージをパースする
pub fn parse_reply(data: &[u8]) -> Result<ParsedReply, Dhcpv6Error> {
    if data.len() < 4 {
        return Err(Dhcpv6Error::Parse("パケットが短すぎます".into()));
    }

    let msg_type = data[0];
    let transaction_id = [data[1], data[2], data[3]];

    // TODO: オプションのパース

    Ok(ParsedReply {
        msg_type,
        transaction_id,
        options_raw: data[4..].to_vec(),
    })
}

#[derive(Debug)]
pub struct ParsedReply {
    pub msg_type: u8,
    pub transaction_id: [u8; 3],
    pub options_raw: Vec<u8>,
}
