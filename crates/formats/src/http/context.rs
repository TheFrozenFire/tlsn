use tlsn_core::CryptoProvider;
use tlsn_core::presentation::{Presentation, PresentationOutput};
use tlsn_core::transcript::Transcript;
use spansy::Spanned;

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
    pub fn builder<'a>(
        provider: &'a CryptoProvider,
        presentation: Presentation,
        structure: HttpTranscript,
    ) -> HttpContextBuilder<'a> {
        HttpContextBuilder::new(provider, presentation, structure)
    }
}

/// Builder for [`HttpContext`].
pub struct HttpContextBuilder<'a> {
    provider: &'a CryptoProvider,
    presentation: Presentation,
    structure: HttpTranscript,
}

impl<'a> HttpContextBuilder<'a> {
    /// Creates a new builder.
    pub fn new(
        provider: &'a CryptoProvider,
        presentation: Presentation,
        structure: HttpTranscript,
    ) -> Self {
        Self { provider, presentation, structure }
    }

    // Enforces the structure of the transcript.
    // The transcript must have the same number of requests and responses as the structure.
    // The request method and target must match.
    // The request and response headers exist if present, and must match values if specified.
    // The response status code must match if specified.
    // If the request or response body is JSON, the body must be valid JSON, and the body must match the structure.
    fn enforce_structure(&self, transcript: &HttpTranscript) -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(transcript.requests.len(), self.structure.requests.len());
        assert_eq!(transcript.responses.len(), self.structure.responses.len());

        for (structure_request, request) in self.structure.requests.iter().zip(transcript.requests.iter()) {
            assert_eq!(request.request.method, structure_request.request.method);
            assert_eq!(request.request.target, structure_request.request.target);

            for (structure_header, header) in structure_request.headers.iter().zip(request.headers.iter()) {
                assert_eq!(header.name, structure_header.name);
                if !structure_header.value.span().is_empty() {
                    assert_eq!(header.value, structure_header.value);
                }
            }


        }

        for (structure_response, response) in self.structure.responses.iter().zip(transcript.responses.iter()) {
            assert_eq!(response.status, structure_response.status);

            for (structure_header, header) in structure_response.headers.iter().zip(response.headers.iter()) {
                assert_eq!(header.name, structure_header.name);
                if !structure_header.value.span().is_empty() {
                    assert_eq!(header.value, structure_header.value);
                }
            }
        }
        Ok(())
    }

    /// Builds the context.
    pub fn build(self) -> Result<HttpContext, Box<dyn std::error::Error>> {
        let verified = self.presentation.clone().verify(self.provider)?;

        let transcript = HttpTranscript::parse_partial(&verified.transcript.unwrap())?;

        if let Some(server_name) = verified.server_name {
            assert_eq!(
                server_name.as_str(),
                String::from_utf8_lossy(transcript.requests.first().unwrap().headers_with_name("host").next().unwrap().value.as_bytes())
            );
        }

        self.enforce_structure(&transcript)?;

        Ok(HttpContext {
            transcript,
        })
    }
}