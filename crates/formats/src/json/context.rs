use spansy::json::JsonValue;

/// A verifier of contextual integrity for JSON.
///
/// See the [module level documentation](crate::context) for more information.
#[derive(Debug)]
pub struct JsonContext {
    value: JsonValue,
}

impl JsonContext {
    /// Creates a new builder.
    pub fn builder(
        value: JsonValue,
        structure: JsonValue,
    ) -> JsonContextBuilder {
        JsonContextBuilder::new(value, structure)
    }
}

/// Builder for [`JsonContext`].
pub struct JsonContextBuilder {
    value: JsonValue,
    structure: JsonValue,
}

impl JsonContextBuilder {
    /// Creates a new builder.
    pub fn new(
        value: JsonValue,
        structure: JsonValue,
    ) -> Self {
        Self { value, structure }
    }

    /// Builds the context.
    pub fn build(self) -> Result<JsonContext, Box<dyn std::error::Error>> {
        Ok(JsonContext { value: self.value })
    }
}