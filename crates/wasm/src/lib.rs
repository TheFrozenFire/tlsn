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
    reveal_sent: HttpReveal,
    reveal_recv: HttpReveal,
) -> Result<Presentation, JsError> {
    let transcript = HttpTranscript::parse(secrets.0.transcript())?;

    let mut builder = secrets.0.transcript_proof_builder();

    // Request
    let request = &transcript.requests[0];

    if reveal_sent.reveal_structure.unwrap_or(false) {
        builder.reveal_sent(&request.without_data())?;
    }

    if reveal_sent.reveal_header_names.unwrap_or(false) {
        for header in &request.headers {
            builder.reveal_sent(&header.without_value())?;
        }
    }

    if reveal_sent.reveal_target.unwrap_or(false) {
        builder.reveal_sent(&request.request.target)?;
    }

    if reveal_sent.reveal_header_values.unwrap_or(false) {
        for header in &request.headers {
            builder.reveal_sent(header)?;
        }
    } else if let Some(headers) = reveal_sent.headers {
        for (name, reveal_value) in headers {
            if let Some(request_headers) = request.headers.get(name) {
                for header in request_headers {
                    if reveal_value {
                        builder.reveal_sent(header)?;
                    } else {
                        builder.reveal_sent(&header.without_value())?;
                    }
                }
            }
        }
    }

    if reveal_sent.reveal_whole_body {
        builder.reveal_sent(&request.body)?;
    } else {
        match &request.body.as_ref().unwrap().content {
            BodyContent::Json(json) => {
                if reveal_sent.reveal_body_json_structure {
                    // TODO: Implement
                }

                if let Some(paths) = reveal_sent.body_json_paths {
                    for path in paths {
                        builder.reveal_sent(json.get(path).unwrap())?;
                    }
                }
            }

            BodyContent::Unknown(span) => {
                builder.reveal_sent(span)?;
            }
        }
    }

    // Response
    let response = &transcript.responses[0];

    if reveal_recv.reveal_structure {
        builder.reveal_recv(&response.without_data())?;
    }

    if reveal_recv.reveal_header_names {
        for header in &response.headers {
            builder.reveal_recv(&header.without_value())?;
        }
    }
    
    if reveal_recv.reveal_target {
        builder.reveal_recv(&response.request.target)?;
    }

    if reveal_recv.reveal_header_values {
        for header in &response.headers {
            builder.reveal_recv(&header)?;
        }
    } else if let Some(headers) = reveal_recv.headers {
        for (name, reveal_value) in headers {
            if let Some(response_headers) = response.headers.get(name) {
                for header in response_headers {
                    if reveal_value {
                        builder.reveal_recv(&header)?;
                    } else {
                        builder.reveal_recv(&header.without_value())?;
                    }
                }
            }
        }
    }

    if reveal_recv.reveal_whole_body {
        builder.reveal_recv(&response.body)?;
    } else {
        match &response.body.as_ref().unwrap().content {
            BodyContent::Json(json) => {
                if reveal_recv.reveal_body_json_structure {
                    // TODO: Implement
                }

                if let Some(paths) = reveal_recv.body_json_paths {
                    for path in paths {
                        builder.reveal_recv(json.get(path).unwrap())?;
                    }
                }
            }

            BodyContent::Unknown(span) => {
                builder.reveal_recv(span)?;
            }

            _ => {}
        }
    }

    let transcript_proof = builder.build()?;

    // Use default crypto provider to build the presentation.
    let provider = CryptoProvider::default();

    let mut builder = attestation.0.presentation_builder(&provider);

    builder
        .identity_proof(secrets.0.identity_proof())
        .transcript_proof(transcript_proof);

    let presentation: Presentation = builder.build()?;

    Ok(presentation)
}