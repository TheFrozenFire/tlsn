//! Tooling for working with HTTP data.

mod commit;
mod context;

use bytes::Bytes;
pub use commit::{DefaultHttpCommitter, HttpCommit, HttpCommitError};
pub use context::HttpContext;

#[doc(hidden)]
pub use spansy::http;
use spansy::json::JsonValue;

pub use http::{
    parse_request, parse_response, Body, BodyContent, Header, HeaderName, HeaderValue, Method,
    Reason, Request, RequestLine, Requests, Response, Responses, Status, Target,
};
use tlsn_core::transcript::{PartialTranscript, Transcript, TranscriptProofBuilder, Direction, TranscriptProofBuilderError};

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
        parseable.set_unauthed(b'*');

        let requests = Requests::new(Bytes::copy_from_slice(parseable.sent_unsafe()))
            .collect::<Result<Vec<_>, _>>()?;
        let responses = Responses::new(Bytes::copy_from_slice(parseable.received_unsafe()))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            requests,
            responses,
        })
    }

    fn reveal_json_structure(&self, builder: &mut TranscriptProofBuilder, direction: Direction, json: &JsonValue) -> Result<(), TranscriptProofBuilderError> {
        match json {
            JsonValue::Object(object) => {
                // Reveal the object structure without its pairs
                match direction {
                    Direction::Sent => {
                        builder.reveal_sent(&object.without_pairs())?;
                    }
                    Direction::Received => {
                        builder.reveal_recv(&object.without_pairs())?;
                    }
                }
    
                // Reveal each key-value pair structure
                for keyvalue in &object.elems {
                    match direction {
                        Direction::Sent => {
                            builder.reveal_sent(&keyvalue.without_value())?;
                        }
                        Direction::Received => {
                            builder.reveal_recv(&keyvalue.without_value())?;
                        }
                    }
    
                    // Recursively reveal the value's structure
                    self.reveal_json_structure(builder, direction, &keyvalue.value)?;
                }
            }
            JsonValue::Array(array) => {
                // Reveal array structure
                match direction {
                    Direction::Sent => {
                        builder.reveal_sent(&array.without_values())?;
                    }
                    Direction::Received => {
                        builder.reveal_recv(&array.without_values())?;
                    }
                }
                
                for value in &array.elems {
                    self.reveal_json_structure(builder, direction, value)?;
                }
            }
            _ => {} // For primitive values, no structure to reveal
        }

        Ok(())
    }

    /// Reveals the structure of the HTTP transcript.
    pub fn reveal_structure(&self, builder: &mut TranscriptProofBuilder) -> Result<(), TranscriptProofBuilderError> {
        for request in &self.requests {
            builder.reveal_sent(&request.without_data())?;
            builder.reveal_sent(&request.request.target)?;
            
            for header in &request.headers {
                builder.reveal_sent(&header.without_value())?;
            }

            if let Some(body) = &request.body {
                match &body.content {
                    BodyContent::Json(json) => {
                        self.reveal_json_structure(builder, Direction::Sent, json)?;
                    }
                    
                    BodyContent::Unknown(unknown) => {
                        builder.reveal_sent(unknown)?;
                    }

                    _ => {}
                }
            }
        }

        for response in &self.responses {
            builder.reveal_recv(&response.without_data())?;

            for header in &response.headers {
                match header.name.as_str().to_lowercase().as_str() {
                    "host" | "content-length" | "content-type" => {
                        builder.reveal_recv(header)?;
                    }
                    _ => {
                        builder.reveal_recv(&header.without_value())?;
                    }
                }
            }

            if let Some(body) = &response.body {
                match &body.content {
                    BodyContent::Json(json) => {
                        self.reveal_json_structure(builder, Direction::Received, json)?;
                    }

                    BodyContent::Unknown(unknown) => {
                        builder.reveal_recv(unknown)?;
                    }

                    _ => {}
                }
            }
        }

        Ok(())
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

        request_ranges = request
            .headers
            .iter()
            .filter(|h| !matches!(h.name.as_str(), "Host" | "Content-Length" | "Content-Type"))
            .map(|h| h.value.span().to_range_set())
            .fold(request_ranges, |acc, e| acc.difference(&e));

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

    #[rstest]
    #[case::ok_empty(fixtures::response::OK_EMPTY)]
    #[case::ok_empty_header(fixtures::response::OK_EMPTY_HEADER)]
    #[case::ok_text(fixtures::response::OK_TEXT)]
    #[case::ok_json(fixtures::response::OK_JSON)]
    fn test_http_transcript_parse_partial_response(#[case] src: &'static [u8]) {
        let transcript = Transcript::new(fixtures::request::GET_EMPTY, src);
        let response = parse_response(src).unwrap();

        let mut response_ranges = response.span().to_range_set();

        response_ranges = response
            .headers
            .iter()
            .filter(|h| !matches!(h.name.as_str(), "Content-Length" | "Content-Type"))
            .map(|h| h.value.span().to_range_set())
            .fold(response_ranges, |acc, e| acc.difference(&e));

        if let Some(body) = &response.body {
            if let BodyContent::Json(json) = &body.content {
                let mut collector = JsonLiteralCollector::new();
                collector.visit_value(json);

                response_ranges = collector
                    .literals
                    .iter()
                    .map(|e| e.to_range_set())
                    .fold(response_ranges, |acc, e| acc.difference(&e));
            }
        }
        
        let partial_transcript = transcript.to_partial(Idx::new([0..transcript.sent().len()]), Idx::new(response_ranges));

        HttpTranscript::parse_partial(&partial_transcript).unwrap();
    }
}