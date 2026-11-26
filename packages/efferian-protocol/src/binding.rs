use crate::wire::strict_enum;

use serde::{Deserialize, Deserializer, de};
use serde_json::{Map, Value};

use crate::{
    ValidationError,
    validate::spend_action_bytes,
    wire::{BoundedBuffer, BoundedJsonError, bounded_json_len},
};

strict_enum! {
    tag = "kind",
    #[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
    pub enum ValueBinding {
        Literal { value: String },
        Arg { name: String },
        Secret { key: String },
    }
}

strict_enum! {
    tag = "kind",
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum ArgBinding {
        Literal { value: String },
        Arg { name: String },
    }
}

impl TryFrom<ValueBinding> for ArgBinding {
    type Error = ValidationError;

    fn try_from(binding: ValueBinding) -> Result<Self, Self::Error> {
        match binding {
            ValueBinding::Literal { value } => Ok(Self::Literal { value }),
            ValueBinding::Arg { name } => Ok(Self::Arg { name }),
            ValueBinding::Secret { .. } => Err(ValidationError::SecretForbiddenInArgv),
        }
    }
}

impl<'de> Deserialize<'de> for ArgBinding {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        ValueBinding::deserialize(d)?
            .try_into()
            .map_err(de::Error::custom)
    }
}

impl ArgBinding {
    pub fn resolve_text(
        &self,
        args: &Map<String, Value>,
        remaining: &mut usize,
    ) -> Result<String, ValidationError> {
        match self {
            Self::Literal { value } => copy_text(value, remaining),
            Self::Arg { name } => resolve_text(argument(args, name)?, remaining),
        }
    }

    pub(crate) fn validate_literal(
        &self,
        validate: impl FnOnce(&str) -> Result<(), ValidationError>,
    ) -> Result<(), ValidationError> {
        if let Self::Literal { value } = self {
            validate(value)?;
        }
        Ok(())
    }
}

strict_enum! {
    tag = "kind",
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum EnvBinding {
        Literal { value: String },
        Secret { key: String },
    }
}

impl TryFrom<ValueBinding> for EnvBinding {
    type Error = ValidationError;

    fn try_from(binding: ValueBinding) -> Result<Self, Self::Error> {
        match binding {
            ValueBinding::Literal { value } => Ok(Self::Literal { value }),
            ValueBinding::Secret { key } => Ok(Self::Secret { key }),
            ValueBinding::Arg { .. } => Err(ValidationError::ArgForbiddenInEnv),
        }
    }
}

impl<'de> Deserialize<'de> for EnvBinding {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        ValueBinding::deserialize(d)?
            .try_into()
            .map_err(de::Error::custom)
    }
}

strict_enum! {
    tag = "kind",
    #[derive(Clone, Debug, PartialEq, Deserialize)]
    pub enum HttpBodyBinding {
        LiteralText { value: String },
        LiteralJson { value: Value },
        ArgText { name: String },
        ArgJson { name: String },
    }
}

impl HttpBodyBinding {
    pub fn resolve(
        &self,
        args: &Map<String, Value>,
        remaining: &mut usize,
    ) -> Result<String, ValidationError> {
        match self {
            Self::LiteralText { value } => copy_text(value, remaining),
            Self::ArgText { name } => resolve_text(argument(args, name)?, remaining),
            Self::LiteralJson { value } => resolve_json(value, remaining),
            Self::ArgJson { name } => resolve_json(argument(args, name)?, remaining),
        }
    }
}

fn argument<'a>(args: &'a Map<String, Value>, name: &str) -> Result<&'a Value, ValidationError> {
    args.get(name).ok_or(ValidationError::MissingArgument)
}

pub(crate) fn copy_text(text: &str, remaining: &mut usize) -> Result<String, ValidationError> {
    spend_action_bytes(remaining, text.len())?;
    Ok(text.to_owned())
}

fn resolve_text(value: &Value, remaining: &mut usize) -> Result<String, ValidationError> {
    match value {
        Value::String(text) => copy_text(text, remaining),
        Value::Bool(true) => copy_text("true", remaining),
        Value::Bool(false) => copy_text("false", remaining),
        Value::Number(number) => {
            let text = number.to_string();
            spend_action_bytes(remaining, text.len())?;
            Ok(text)
        }
        _ => Err(ValidationError::InvalidTextArgument),
    }
}

fn resolve_json(value: &Value, remaining: &mut usize) -> Result<String, ValidationError> {
    let bytes = bounded_json_len(*remaining, |writer| serde_json::to_writer(writer, value))
        .map_err(|error| match error {
            BoundedJsonError::TooLarge => ValidationError::ActionLimit,
            BoundedJsonError::Serialization => ValidationError::InvalidJson,
        })?;
    let mut buffer = Vec::with_capacity(bytes);
    serde_json::to_writer(BoundedBuffer::new(&mut buffer, bytes), value)
        .map_err(|_| ValidationError::InvalidJson)?;
    spend_action_bytes(remaining, buffer.len())?;
    String::from_utf8(buffer).map_err(|_| ValidationError::InvalidJson)
}
