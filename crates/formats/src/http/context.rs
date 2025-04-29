use tlsn_core::CryptoProvider;
use tlsn_core::presentation::Presentation;

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
    ) -> HttpContextBuilder<'a> {
        HttpContextBuilder::new(provider, presentation)
    }
}

/// Builder for [`HttpContext`].
pub struct HttpContextBuilder<'a> {
    provider: &'a CryptoProvider,
    presentation: Presentation,
}

impl<'a> HttpContextBuilder<'a> {
    /// Creates a new builder.
    pub fn new(provider: &'a CryptoProvider, presentation: Presentation) -> Self {
        Self { provider, presentation }
    }

    /// Builds the context.
    pub fn build(self) -> Result<HttpContext, Box<dyn std::error::Error>> {
        let verified = self.presentation.verify(self.provider)?;

        let transcript = HttpTranscript::parse_partial(&verified.transcript.unwrap())?;

        Ok(HttpContext {
            transcript,
        })
    }
}