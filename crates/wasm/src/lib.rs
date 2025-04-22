//! TLSNotary WASM bindings.

#![cfg(target_arch = "wasm32")]
#![deny(unreachable_pub, unused_must_use, clippy::all)]
#![allow(non_snake_case)]

pub(crate) mod io;
mod log;
pub mod prover;
#[cfg(feature = "test")]
pub mod tests;
pub mod types;
pub mod verifier;

pub use log::{LoggingConfig, LoggingLevel};

use tlsn_core::{transcript::Direction, CryptoProvider};
use tlsn_formats::http::{BodyContent, HttpTranscript};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use crate::types::{Attestation, Presentation, Reveal, Secrets, HttpReveal};

#[cfg(feature = "test")]
pub use tests::*;

/// Initializes the module.
#[wasm_bindgen]
pub async fn initialize(
    logging_config: Option<LoggingConfig>,
    thread_count: usize,
) -> Result<(), JsValue> {
    log::init_logging(logging_config);

    JsFuture::from(web_spawn::start_spawner()).await?;

    // Initialize rayon global thread pool.
    rayon::ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .spawn_handler(|thread| {
            // Drop join handle.
            let _ = web_spawn::spawn(move || thread.run());
            Ok(())
        })
        .build_global()
        .unwrap_throw();

    Ok(())
}

/// Builds a presentation.
#[wasm_bindgen]
pub fn build_presentation(
    attestation: &Attestation,
    secrets: &Secrets,
    reveal: Reveal,
) -> Result<Presentation, JsError> {
    let provider = CryptoProvider::default();

    let mut builder = attestation.0.presentation_builder(&provider);

    builder.identity_proof(secrets.0.identity_proof());

    let mut proof_builder = secrets.0.transcript_proof_builder();

    for range in reveal.sent.iter() {
        proof_builder.reveal(range, Direction::Sent)?;
    }

    for range in reveal.recv.iter() {
        proof_builder.reveal(range, Direction::Received)?;
    }

    builder.transcript_proof(proof_builder.build()?);

    builder
        .build()
        .map(Presentation::from)
        .map_err(JsError::from)
}

// Builds a presentation from an HTTP transcript.
#[wasm_bindgen]
pub fn build_http_presentation(
    attestation: &Attestation,
    secrets: &Secrets,
    reveal: HttpReveal,
) -> Result<Presentation, JsError> {
    let provider = CryptoProvider::default();

    let transcript = HttpTranscript::parse(secrets.0.transcript())?;

    let mut builder = attestation.0.presentation_builder(&provider);

    builder.identity_proof(secrets.0.identity_proof());

    let mut proof_builder = secrets.0.transcript_proof_builder();

    // Request
    let request = &transcript.requests[0];

    if reveal.sent.reveal_structure.unwrap_or(false) {
        proof_builder.reveal_sent(&request.without_data())?;
    }

    if reveal.sent.reveal_header_names.unwrap_or(false) {
        for header in &request.headers {
            proof_builder.reveal_sent(&header.without_value())?;
        }
    }

    if reveal.sent.reveal_target.unwrap_or(false) {
        proof_builder.reveal_sent(&request.request.target)?;
    }

    if reveal.sent.reveal_header_values.unwrap_or(false) {
        for header in &request.headers {
            proof_builder.reveal_sent(header)?;
        }
    } else if let Some(headers) = reveal.sent.headers {
        for (name, reveal_value) in headers {
            let request_headers: Vec<_> = request.headers.iter().filter(|header| header.name.as_str().to_lowercase() == name.to_lowercase()).collect();
            if !request_headers.is_empty() {
                for header in request_headers {
                    if reveal_value {
                        proof_builder.reveal_sent(header)?;
                    } else {
                        proof_builder.reveal_sent(&header.without_value())?;
                    }
                }
            }
        }
    }

    if reveal.sent.reveal_whole_body.unwrap_or(false) {
        if let Some(body) = &request.body {
            proof_builder.reveal_sent(body)?;
        }
    } else {
        if let Some(body) = &request.body {
            match &body.content {
                BodyContent::Json(json) => {
                    if reveal.sent.reveal_body_json_structure.unwrap_or(false) {
                        // TODO: Implement
                    }

                    if let Some(paths) = reveal.sent.body_json_paths {
                        for path in paths {
                            proof_builder.reveal_sent(json.get(path.as_str()).unwrap())?;
                        }
                    }
                }

                BodyContent::Unknown(span) => {
                    proof_builder.reveal_sent(span)?;
                }

                _ => {}
            }
        }
    }

    // Response
    let response = &transcript.responses[0];

    if reveal.recv.reveal_structure.unwrap_or(false) {
        proof_builder.reveal_recv(&response.without_data())?;
    }

    if reveal.recv.reveal_header_names.unwrap_or(false) {
        for header in &response.headers {
            proof_builder.reveal_recv(&header.without_value())?;
        }
    }

    if reveal.recv.reveal_header_values.unwrap_or(false) {
        for header in &response.headers {
            proof_builder.reveal_recv(header)?;
        }
    } else if let Some(headers) = reveal.recv.headers {
        for (name, reveal_value) in headers {
            let response_headers: Vec<_> = response.headers.iter().filter(|header| header.name.as_str().to_lowercase() == name.to_lowercase()).collect();
            if !response_headers.is_empty() {
                for header in response_headers {
                    if reveal_value {
                        proof_builder.reveal_recv(header)?;
                    } else {
                        proof_builder.reveal_recv(&header.without_value())?;
                    }
                }
            }
        }
    }

    if reveal.recv.reveal_whole_body.unwrap_or(false) {
        if let Some(body) = &response.body {
            proof_builder.reveal_recv(body)?;
        }
    } else {
        if let Some(body) = &response.body {
            match &body.content {
                BodyContent::Json(json) => {
                    if reveal.recv.reveal_body_json_structure.unwrap_or(false) {
                    // TODO: Implement
                    }

                    if let Some(paths) = reveal.recv.body_json_paths {
                        for path in paths {
                            proof_builder.reveal_recv(json.get(path.as_str()).unwrap())?;
                        }
                    }
                }

                BodyContent::Unknown(span) => {
                    proof_builder.reveal_recv(span)?;
                }

                _ => {}
            }
        }
    }

    builder.transcript_proof(proof_builder.build()?);

    builder
        .build()
        .map(Presentation::from)
        .map_err(JsError::from)
}