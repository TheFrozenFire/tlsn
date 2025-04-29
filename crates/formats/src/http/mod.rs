//! Tooling for working with HTTP data.

mod commit;
mod context;

use bytes::Bytes;
pub use commit::{DefaultHttpCommitter, HttpCommit, HttpCommitError};
pub use context::HttpContext;

#[doc(hidden)]
pub use spansy::http;

pub use http::{
    parse_request, parse_response, Body, BodyContent, Header, HeaderName, HeaderValue, Method,
    Reason, Request, RequestLine, Requests, Response, Responses, Status, Target,
};
use tlsn_core::transcript::{PartialTranscript, Transcript};

/// The kind of HTTP message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageKind {
    /// An HTTP request.
    Request,
    /// An HTTP response.
    Response,
}

/// An HTTP transcript.
#[derive(Debug)]
pub struct HttpTranscript {
    /// The requests sent to the server.
    pub requests: Vec<Request>,
    /// The responses received from the server.
    pub responses: Vec<Response>,
}

impl HttpTranscript {
    /// Parses the HTTP transcript from the provided transcripts.
    pub fn parse(transcript: &Transcript) -> Result<Self, spansy::ParseError> {
        let requests = Requests::new(Bytes::copy_from_slice(transcript.sent()))
            .collect::<Result<Vec<_>, _>>()?;
        let responses = Responses::new(Bytes::copy_from_slice(transcript.received()))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            requests,
            responses,
        })
    }

    /// Parses the HTTP transcript from the provided partial transcript,
    /// setting all unauthenticated data to null bytes.
    pub fn parse_partial(transcript: &PartialTranscript) -> Result<Self, spansy::ParseError> {
        let mut parseable = transcript.clone();
        parseable.set_unauthed(0);

        let requests = Requests::new(Bytes::copy_from_slice(parseable.sent_unsafe()))
            .collect::<Result<Vec<_>, _>>()?;
        let responses = Responses::new(Bytes::copy_from_slice(parseable.received_unsafe()))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            requests,
            responses,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;
    use spansy::{
        http::{parse_request, BodyContent},
        json::{
            JsonValue, JsonVisit
        }, json as json_types, Spanned
    };
    use tlsn_core::transcript::{Transcript, Idx};
    use tlsn_data_fixtures::http as fixtures;
    use rangeset::{ Difference, ToRangeSet };

    struct JsonLiteralCollector {
        literals: Vec<JsonValue>,
    }

    impl JsonLiteralCollector {
        fn new() -> Self {
            Self { literals: Vec::new() }
        }
    }

    impl JsonVisit for JsonLiteralCollector {
        fn visit_string(&mut self, node: &json_types::String) { self.literals.push(JsonValue::String(node.clone())); }
        fn visit_number(&mut self, node: &json_types::Number) { self.literals.push(JsonValue::Number(node.clone())); }
        fn visit_bool(&mut self, node: &json_types::Bool) { self.literals.push(JsonValue::Bool(node.clone())); }
        fn visit_null(&mut self, node: &json_types::Null) { self.literals.push(JsonValue::Null(node.clone())); }
    }

    #[rstest]
    #[case::get_empty(fixtures::request::GET_EMPTY)]
    #[case::get_empty_header(fixtures::request::GET_EMPTY_HEADER)]
    #[case::get_with_header(fixtures::request::GET_WITH_HEADER)]
    #[case::post_json(fixtures::request::POST_JSON)]
    fn test_http_transcript_parse_partial_request(#[case] src: &'static [u8]) {
        let transcript = Transcript::new(src, []);
        let request = parse_request(src).unwrap();

        let mut request_ranges = request.span().to_range_set();

        if let Some(body) = &request.body {
            if let BodyContent::Json(json) = &body.content {
                let mut collector = JsonLiteralCollector::new();
                collector.visit_value(json);

                request_ranges = collector
                    .literals
                    .iter()
                    .map(|e| e.to_range_set())
                    .fold(request_ranges, |acc, e| acc.difference(&e));                
            }
        }

        let partial_transcript = transcript.to_partial(Idx::new(request_ranges), Idx::new([]));

        HttpTranscript::parse_partial(&partial_transcript).unwrap();
    }
}