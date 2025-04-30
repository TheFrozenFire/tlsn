use tlsn_core::CryptoProvider;
use tlsn_core::presentation::{Presentation, PresentationOutput};
use tlsn_core::transcript::Transcript;
use spansy::{ http::Request, Spanned };

use crate::http::HttpTranscript;

/// A verifier of contextual integrity for HTTP presentations.
///
/// See the [module level documentation](crate::context) for more information.
#[derive(Debug)]
pub struct HttpContext {
    transcript: HttpTranscript,
}

impl HttpContext {
    /// Creates a new builder.
    pub fn builder(
        presentation: PresentationOutput,
        structure: HttpTranscript,
    ) -> HttpContextBuilder {
        HttpContextBuilder::new(presentation, structure)
    }
}

/// Builder for [`HttpContext`].
pub struct HttpContextBuilder {
    presentation: PresentationOutput,
    structure: HttpTranscript,
}

impl HttpContextBuilder {
    /// Creates a new builder.
    pub fn new(
        presentation: PresentationOutput,
        structure: HttpTranscript,
    ) -> Self {
        Self { presentation, structure }
    }

    // Enforces the request target.
    // The request target must match the structure target.
    // If the structure target starts with "/", the request target may be an absolute URL or a relative URL
    // If the structure target does not start with "/", the request target must be a full URL that matches the structure target.
    fn enforce_request_target(&self, request: &Request, structure_request: &Request) -> Result<(), Box<dyn std::error::Error>> {
        let structure_target = structure_request.request.target.as_str();
        let request_target = request.request.target.as_str();

        if structure_target.starts_with("/") {
            if request_target.starts_with("/") {
                assert_eq!(request_target, structure_target, "Request target mismatch");
            } else {
                let request_url = url::Url::parse(request_target)?;
                let path_and_query = if let Some(query) = request_url.query() {
                    format!("{}?{}", request_url.path(), query)
                } else {
                    request_url.path().to_string()
                };
                assert_eq!(path_and_query, structure_target, "Request target mismatch");
            }
        } else {
            assert_eq!(request_target, structure_target, "Request target mismatch");
        }

        Ok(())
    }

    // Enforces the structure of the transcript.
    // The transcript must have the same number of requests and responses as the structure.
    // The request method and target must match.
    // The request and response headers exist if present, and must match values if specified.
    // The response status code must match if specified.
    // If the request or response body is JSON, the body must be valid JSON, and the body must match the structure.
    fn enforce_structure(&self, transcript: &HttpTranscript) -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(transcript.requests.len(), self.structure.requests.len(), "Request count mismatch");
        assert_eq!(transcript.responses.len(), self.structure.responses.len(), "Response count mismatch");

        for (structure_request, request) in self.structure.requests.iter().zip(transcript.requests.iter()) {
            assert_eq!(request.request.method, structure_request.request.method, "Request method mismatch");
            
            self.enforce_request_target(request, structure_request)?;

            let structure_headers = structure_request.headers.iter()
                .filter(|h| !["content-length"].contains(&h.name.as_str().to_lowercase().as_str()));

            for structure_header in structure_headers {
                let header = request.headers_with_name(&structure_header.name.as_str()).next()
                    .ok_or_else(|| format!("Missing required header: {}", structure_header.name.as_str()))?;

                if !structure_header.value.span().is_empty() {
                    assert_eq!(
                        header.value.as_bytes(),
                        structure_header.value.as_bytes(),
                        "Header value mismatch: {}",
                        structure_header.name.as_str(),
                    );
                }
            }
        }

        for (structure_response, response) in self.structure.responses.iter().zip(transcript.responses.iter()) {
            assert_eq!(response.status, structure_response.status, "Response status mismatch");

            let structure_headers = structure_response.headers.iter()
                .filter(|h| !["content-length"].contains(&h.name.as_str().to_lowercase().as_str()));

            for structure_header in structure_headers {
                let header = response.headers_with_name(&structure_header.name.as_str()).next()
                    .ok_or_else(|| format!("Missing required header: {}", structure_header.name.as_str()))?;

                if !structure_header.value.span().is_empty() {
                    assert_eq!(
                        header.value.as_bytes(),
                        structure_header.value.as_bytes(),
                        "Header value mismatch: {}",
                        structure_header.name.as_str()
                    );
                }
            }
        }
        Ok(())
    }

    /// Builds the context.
    pub fn build(self) -> Result<HttpContext, Box<dyn std::error::Error>> {
        let transcript = HttpTranscript::parse_partial(&self.presentation.transcript.as_ref().unwrap())?;

        self.enforce_structure(&transcript)?;

        Ok(HttpContext {
            transcript,
        })
    }
}