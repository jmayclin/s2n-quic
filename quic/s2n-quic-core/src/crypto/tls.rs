// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{application::ServerName, crypto::CryptoSuite, transport};
use bytes::Buf;
pub use bytes::{Bytes, BytesMut};
use core::{
    convert::TryFrom,
    fmt::Debug,
    task::{Poll, Waker},
};
use s2n_codec::EncoderValue;
use zerocopy::{AsBytes, FromBytes, Unaligned};

#[cfg(any(test, feature = "testing"))]
pub mod testing;

/// Holds all application parameters which are exchanged within the TLS handshake.
#[derive(Debug)]
pub struct ApplicationParameters<'a> {
    /// Encoded transport parameters
    pub transport_parameters: &'a [u8],
}

//= https://www.rfc-editor.org/rfc/rfc9000#section-4
//= type=TODO
//= tracking-issue=332
//# To avoid excessive buffering at multiple layers, QUIC implementations
//# SHOULD provide an interface for the cryptographic protocol
//# implementation to communicate its buffering limits.

pub trait Context<Crypto: CryptoSuite> {
    fn on_handshake_keys(
        &mut self,
        key: Crypto::HandshakeKey,
        header_key: Crypto::HandshakeHeaderKey,
    ) -> Result<(), transport::Error>;

    fn on_zero_rtt_keys(
        &mut self,
        key: Crypto::ZeroRttKey,
        header_key: Crypto::ZeroRttHeaderKey,
        application_parameters: ApplicationParameters,
    ) -> Result<(), transport::Error>;

    fn on_one_rtt_keys(
        &mut self,
        key: Crypto::OneRttKey,
        header_key: Crypto::OneRttHeaderKey,
        application_parameters: ApplicationParameters,
    ) -> Result<(), transport::Error>;

    fn on_server_name(
        &mut self,
        server_name: crate::application::ServerName,
    ) -> Result<(), transport::Error>;

    fn on_application_protocol(
        &mut self,
        application_protocol: Bytes,
    ) -> Result<(), transport::Error>;

    //= https://www.rfc-editor.org/rfc/rfc9001#section-4.1.1
    //# The TLS handshake is considered complete when the
    //# TLS stack has reported that the handshake is complete.  This happens
    //# when the TLS stack has both sent a Finished message and verified the
    //# peer's Finished message.
    fn on_handshake_complete(&mut self) -> Result<(), transport::Error>;

    /// Receives data from the initial packet space
    ///
    /// A `max_len` may be provided to indicate how many bytes the TLS implementation
    /// is willing to buffer.
    fn receive_initial(&mut self, max_len: Option<usize>) -> Option<Bytes>;

    /// Receives data from the handshake packet space
    ///
    /// A `max_len` may be provided to indicate how many bytes the TLS implementation
    /// is willing to buffer.
    fn receive_handshake(&mut self, max_len: Option<usize>) -> Option<Bytes>;

    /// Receives data from the application packet space
    ///
    /// A `max_len` may be provided to indicate how many bytes the TLS implementation
    /// is willing to buffer.
    fn receive_application(&mut self, max_len: Option<usize>) -> Option<Bytes>;

    fn can_send_initial(&self) -> bool;
    fn send_initial(&mut self, transmission: Bytes);

    fn can_send_handshake(&self) -> bool;
    fn send_handshake(&mut self, transmission: Bytes);

    fn can_send_application(&self) -> bool;
    fn send_application(&mut self, transmission: Bytes);

    fn waker(&self) -> &Waker;
}

pub trait Endpoint: 'static + Sized + Send {
    type Session: Session;

    fn new_server_session<Params: EncoderValue>(
        &mut self,
        transport_parameters: &Params,
    ) -> Self::Session;

    fn new_client_session<Params: EncoderValue>(
        &mut self,
        transport_parameters: &Params,
        server_name: ServerName,
    ) -> Self::Session;

    /// The maximum length of a tag for any algorithm that may be negotiated
    fn max_tag_length(&self) -> usize;
}

pub trait Session: CryptoSuite + Sized + Send + Debug {
    fn poll<C: Context<Self>>(&mut self, context: &mut C) -> Poll<Result<(), transport::Error>>;
}

#[derive(Copy, Clone, Debug)]
#[allow(non_camel_case_types)]
pub enum CipherSuite {
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
    Unknown,
}

impl From<u16> for CipherSuite {
    fn from(item: u16) -> Self {
        const tag1: u16 = (0x13 << 8) + 0x1;
        const tag2: u16 = (0x13 << 8) + 0x2;
        const tag3: u16 = (0x13 << 8) + 0x3;
        match item {
            tag1 => Self::TLS_AES_128_GCM_SHA256,
            tag2 => Self::TLS_AES_256_GCM_SHA384,
            tag3 => Self::TLS_CHACHA20_POLY1305_SHA256,
            _ => Self::Unknown,
        }
    }
}

impl crate::event::IntoEvent<crate::event::builder::CipherSuite> for CipherSuite {
    #[inline]
    fn into_event(self) -> crate::event::builder::CipherSuite {
        use crate::event::builder::CipherSuite::*;
        match self {
            Self::TLS_AES_128_GCM_SHA256 => TLS_AES_128_GCM_SHA256 {},
            Self::TLS_AES_256_GCM_SHA384 => TLS_AES_256_GCM_SHA384 {},
            Self::TLS_CHACHA20_POLY1305_SHA256 => TLS_CHACHA20_POLY1305_SHA256 {},
            Self::Unknown => Unknown {},
        }
    }
}

impl crate::event::IntoEvent<crate::event::api::CipherSuite> for CipherSuite {
    #[inline]
    fn into_event(self) -> crate::event::api::CipherSuite {
        let builder: crate::event::builder::CipherSuite = self.into_event();
        builder.into_event()
    }
}

macro_rules! handshake_type {
    ($($variant:ident($value:literal)),* $(,)?) => {
        #[derive(Debug, PartialEq, Eq, AsBytes, Unaligned)]
        #[repr(u8)]
        pub enum HandshakeType {
            $($variant = $value),*
        }

        impl TryFrom<u8> for HandshakeType {
            type Error = ();

            #[inline]
            fn try_from(value: u8) -> Result<Self, Self::Error> {
                match value {
                    $($value => Ok(Self::$variant),)*
                    _ => Err(()),
                }
            }
        }
    };
}

//= https://www.rfc-editor.org/rfc/rfc5246#A.4
//# enum {
//#     hello_request(0), client_hello(1), server_hello(2),
//#     certificate(11), server_key_exchange (12),
//#     certificate_request(13), server_hello_done(14),
//#     certificate_verify(15), client_key_exchange(16),
//#     finished(20)
//#     (255)
//# } HandshakeType;
handshake_type!(
    HelloRequest(0),
    ClientHello(1),
    ServerHello(2),
    Certificate(11),
    ServerKeyExchange(12),
    CertificateRequest(13),
    ServerHelloDone(14),
    CertificateVerify(15),
    ClientKeyExchange(16),
    Finished(20),
);

//= https://www.rfc-editor.org/rfc/rfc5246#A.4
//# struct {
//#     HandshakeType msg_type;
//#     uint24 length;
//#     select (HandshakeType) {
//#         case hello_request:       HelloRequest;
//#         case client_hello:        ClientHello;
//#         case server_hello:        ServerHello;
//#         case certificate:         Certificate;
//#         case server_key_exchange: ServerKeyExchange;
//#         case certificate_request: CertificateRequest;
//#         case server_hello_done:   ServerHelloDone;
//#         case certificate_verify:  CertificateVerify;
//#         case client_key_exchange: ClientKeyExchange;
//#         case finished:            Finished;
//#   } body;
//# } Handshake;
#[derive(Clone, Copy, Debug, AsBytes, FromBytes, Unaligned)]
#[repr(C)]
pub struct HandshakeHeader {
    msg_type: u8,
    length: [u8; 3],
}

impl HandshakeHeader {
    #[inline]
    pub fn msg_type(self) -> Option<HandshakeType> {
        HandshakeType::try_from(self.msg_type).ok()
    }

    #[inline]
    pub fn len(self) -> usize {
        let mut len = [0u8; 4];
        len[1..].copy_from_slice(&self.length);
        let len = u32::from_be_bytes(len);
        len as _
    }

    #[inline]
    pub fn is_empty(self) -> bool {
        self.len() == 0
    }
}

s2n_codec::zerocopy_value_codec!(HandshakeHeader);

macro_rules! extension_type {
    ($($variant:ident($value:literal)),* $(,)?) => {
        #[derive(Debug, PartialEq, Eq, AsBytes, Unaligned)]
        #[repr(u8)]
        pub enum ExtensionType {
            $($variant = $value),*
        }

        impl TryFrom<u16> for ExtensionType {
            type Error = ();

            #[inline]
            fn try_from(value: u16) -> Result<Self, Self::Error> {
                match value {
                    $($value => Ok(Self::$variant),)*
                    _ => Err(()),
                }
            }
        }
    };
}

extension_type!(
    server_name(0),
    max_fragment_length(1),
    status_request(5),
    supported_groups(10),
    ec_point_formats(11),
    signature_algorithms(13),
    use_srtp(14),
    heartbeat(15),
    application_layer_protocol_negotiation(16),
    signed_certificate_timestamp(18),
    client_certificate_type(19),
    server_certificate_type(20),
    padding(21),
    extended_master_secret(23),
    session_ticket(35),
    reserved_one(40), // https://mailarchive.ietf.org/arch/msg/tls/vylBCK_8kOaybzcrVigbCTq9okk/
    pre_shared_key(41),
    early_data(42),
    supported_versions(43),
    cookie(44),
    psk_key_exchange_modes(45),
    reserved_two(46), // https://mailarchive.ietf.org/arch/msg/tls/vylBCK_8kOaybzcrVigbCTq9okk/
    certificate_authorities(47),
    oid_filters(48),
    post_handshake_auth(49),
    signature_algorithms_cert(50),
    key_share(51),
    quic_transport_parameters(57),
);

/*
     uint16 ProtocolVersion;
     opaque Random[32];

     uint8 CipherSuite[2];    /* Cryptographic suite selector */

     struct {
         ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
         Random random;
         opaque legacy_session_id<0..32>;
         CipherSuite cipher_suites<2..2^16-2>;
         opaque legacy_compression_methods<1..2^8-1>;
         Extension extensions<8..2^16-1>;
     } ClientHello;
*/

#[derive(Debug)]
pub struct Extension {
    pub flavor: ExtensionType,
    payload: Vec<u8>,
}

pub struct NonContiguousBuffer<'a> {
    slices: &'a [&'a [u8]],
    slice: usize,
    byte: usize,
}

impl<'a> NonContiguousBuffer<'a> {
    fn new(chunks: &'a [&'a [u8]]) -> Self {
        NonContiguousBuffer {
            slices: chunks,
            slice: 0,
            byte: 0,
        }
    }
}

impl<'a> bytes::buf::Buf for NonContiguousBuffer<'a> {
    fn remaining(&self) -> usize {
        if self.slice == self.slices.len() {
            return 0;
        }
        // add the rest of the bytes
        let mut remaining = 0;
        remaining += self.slices[self.slice][self.byte..].len();
        for i in (self.slice + 1)..(self.slices.len()) {
            remaining += self.slices[i].len();
        }
        remaining
    }

    fn chunk(&self) -> &[u8] {
        if self.slice == self.slices.len() {
            return &[];
        }
        // does this internally call the advance thing to deal with noncontiguous?
        // when does this return the empty slice.
        &self.slices[self.slice][self.byte..]
    }

    fn advance(&mut self, mut cnt: usize) {
        // maybe consume from multiple slices
        while cnt != 0 {
            let remaining_in_slice = self.slices[self.slice].len() - self.byte;
            if remaining_in_slice >= cnt {
                self.byte += cnt;
                // check if end of slice
                if self.byte == self.slices[self.slice].len() {
                    self.slice += 1;
                    self.byte = 0;
                }
                break;
            } else {
                // consume the rest of the current slice
                cnt -= remaining_in_slice;
                self.slice += 1;
                self.byte = 0;
            }
        }
    }
}

#[derive(Debug)]
pub struct ClientHello {
    pub sni: Option<Bytes>,
    pub alpn: Option<Bytes>,
}

impl ClientHello {
    const ALPN_TAG: u16 = 16;
    const SNI_TAG: u16 = 0;

    pub fn from_bytes(payload: &[&[u8]]) -> Self {
        let mut buffer = NonContiguousBuffer::new(payload);

        buffer.advance(2); // legacy_version
        buffer.advance(32); // random
        println!("read in legacy version and random");

        let session_length = buffer.get_u8();
        buffer.advance(session_length as usize);

        let cipher_suite_length: u16 = buffer.get_u16();
        buffer.advance(cipher_suite_length as usize);

        let compression_length = buffer.get_u8();
        buffer.advance(compression_length as usize);
        println!("starting extension stuff");
        let extension_length = buffer.get_u16();


        // now looking at the alpn (16) and maybe sni (0)
        let mut sni = Option::None;
        let mut alpn = Option::None;
        while buffer.has_remaining() {
            let extension_type = buffer.get_u16();
            let extension_payload_length = buffer.get_u16();
            println!("Ext:{}, Length: {}", extension_type, extension_payload_length);
            if extension_type == Self::ALPN_TAG {
                alpn = Some(buffer.copy_to_bytes(extension_payload_length as usize))
            } else if extension_type == Self::SNI_TAG {
                sni = Some(buffer.copy_to_bytes(extension_payload_length as usize))
            } else {
                buffer.advance(extension_payload_length as usize);
            }
        }
        ClientHello { sni, alpn }
    }

    pub fn sni(&self) -> Option<Bytes> {
        return self.sni.clone();
    }

    pub fn alpn(&self) -> Option<Bytes> {
        return self.alpn.clone();
    }
}
