use tlsn_core::{connection::ServerName, presentation::PresentationOutput};
use spansy::{ http::{Request, Body, BodyContent}, json::JsonValue, Spanned };

use crate::http::HttpTranscript;
use crate::json::JsonContext;

/// A verifier of contextual integrity for HTTP presentations.
///
/// See the [module level documentation](crate::context) for more information.
#[derive(Debug)]
pub struct HttpContext {
    server_name: Option<ServerName>,
    request_bodies: Vec<BodyContext>,
    response_bodies: Vec<BodyContext>,
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

    /// Enforces the body of an HTTP request or response.
    fn enforce_body(&self, structure_body: &Body, request_body: &Body) -> Result<BodyContext, Box<dyn std::error::Error>> {
        match (&structure_body.content, &request_body.content) {
            (BodyContent::Json(structure_json), BodyContent::Json(request_json)) => {
                Ok(BodyContext::Json(JsonContext::builder(structure_json.clone(), request_json.clone()).build()?))
            }

            (BodyContent::Unknown(structure_unknown), BodyContent::Unknown(request_unknown)) => {
                assert_eq!(structure_unknown.as_bytes(), request_unknown.as_bytes(), "Body content mismatch");
                Ok(BodyContext::Unknown(request_unknown.clone().to_bytes()))
            }

            _ => {
                return Err("Body type mismatch".into());
            }
        }
    }

    // Enforces the request target.
    // The request target must match the structure target.
    // If the structure target starts with "/", the request target may be an absolute URL or a relative URL
    // If the structure target does not start with "/", the request target must be a full URL that matches the structure target.
    fn enforce_request_target(&self, request: &Request, structure_request: &Request) -> Result<(), Box<dyn std::error::Error>> {
        let structure_target = structure_request.request.target.as_str();
        let request_target = request.request.target.as_str();

        let base = url::Url::parse("https://example.com")?;

        let structure_url = base.join(structure_target)?;
        let request_url = base.join(request_target)?;

        let structure_path_and_query = if let Some(query) = structure_url.query() {
            format!("{}?{}", structure_url.path(), query)
        } else {
            structure_url.path().to_string()
        };

        let request_path_and_query = if let Some(query) = request_url.query() {
            format!("{}?{}", request_url.path(), query)
        } else {
            request_url.path().to_string()
        };

        assert_eq!(request_path_and_query, structure_path_and_query, "Request target mismatch");
        if !structure_target.starts_with("/") {
            assert_eq!(request_url.host_str(), structure_url.host_str(), "Request target mismatch");
        }

        Ok(())
    }

    // Enforces the structure of the transcript.
    // The transcript must have the same number of requests and responses as the structure.
    // The request method and target must match.
    // The request and response headers exist if present, and must match values if specified.
    // The response status code must match if specified.
    // If the request or response body is JSON, the body must be valid JSON, and the body must match the structure.
    fn enforce_structure(&self, transcript: &HttpTranscript) -> Result<HttpContext, Box<dyn std::error::Error>> {
        assert_eq!(transcript.requests.len(), self.structure.requests.len(), "Request count mismatch");
        assert_eq!(transcript.responses.len(), self.structure.responses.len(), "Response count mismatch");

        let mut request_bodies = Vec::new();
        let mut response_bodies = Vec::new();

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

            if let Some(structure_body) = &structure_request.body {
                if let Some(request_body) = &request.body {
                    request_bodies.push(self.enforce_body(structure_body, request_body)?);
                } else {
                    return Err("Request body missing".into());
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

            if let Some(structure_body) = &structure_response.body {
                if let Some(response_body) = &response.body {
                    response_bodies.push(self.enforce_body(structure_body, response_body)?);
                } else {
                    return Err("Response body missing".into());
                }
            }
        }

        Ok(HttpContext {
            server_name: self.presentation.server_name.clone(),
            request_bodies,
            response_bodies,
        })
    }

    /// Builds the context.
    pub fn build(self) -> Result<HttpContext, Box<dyn std::error::Error>> {
        let transcript = HttpTranscript::parse_partial(&self.presentation.transcript.as_ref().unwrap())?;

        self.enforce_structure(&transcript)
    }
}

/// The context of a body.
#[derive(Debug)]
pub enum BodyContext {
    /// The body is JSON.
    Json(JsonContext),
    /// The body is unknown.
    Unknown(bytes::Bytes),
}

