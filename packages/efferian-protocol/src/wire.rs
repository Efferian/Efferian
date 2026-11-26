use std::{collections::BTreeMap, fmt};

use serde::{
    Deserialize, Deserializer,
    de::{MapAccess, Visitor, value::MapAccessDeserializer},
};

/// Serde's default struct decoder also accepts positional sequences.
pub(crate) fn deserialize_object<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    struct ObjectVisitor<T>(std::marker::PhantomData<T>);

    impl<'de, T: Deserialize<'de>> Visitor<'de> for ObjectVisitor<T> {
        type Value = T;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("an object")
        }

        fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
            T::deserialize(MapAccessDeserializer::new(map))
        }
    }

    deserializer.deserialize_map(ObjectVisitor(std::marker::PhantomData))
}

pub(crate) fn deserialize_unique_map<'de, V, D>(
    deserializer: D,
) -> Result<BTreeMap<String, V>, D::Error>
where
    V: Deserialize<'de>,
    D: Deserializer<'de>,
{
    struct UniqueMap<V>(std::marker::PhantomData<V>);

    impl<'de, V: Deserialize<'de>> Visitor<'de> for UniqueMap<V> {
        type Value = BTreeMap<String, V>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("an object with unique keys")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut entries = BTreeMap::new();
            while let Some(key) = map.next_key()? {
                if entries.contains_key(&key) {
                    return Err(serde::de::Error::custom("duplicate map key"));
                }
                entries.insert(key, map.next_value()?);
            }
            Ok(entries)
        }
    }

    deserializer.deserialize_map(UniqueMap(std::marker::PhantomData))
}

/// Define a named, closed object with the same fields in Serde and OpenAPI.
macro_rules! strict_struct {
    ($($definition:tt)*) => {
        $crate::wire::wire_struct!([#[serde(deny_unknown_fields)]] $($definition)*);
    };
}

pub(crate) use strict_struct;

/// Decode named fields from a map. The caller chooses the unknown-field policy.
macro_rules! wire_struct {
    (
        [$($unknown_fields:tt)*]
        $(#[$attr:meta])*
        $vis:vis struct $name:ident {
            $($(#[$field_attr:meta])* $field_vis:vis $field:ident: $type:ty $(=> ($($schema:tt)*))?),* $(,)?
        }
    ) => {
        $(#[$attr])*
        #[derive(serde::Serialize)]
        $($unknown_fields)*
        #[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
        $vis struct $name {
            $($(#[$field_attr])* $(#[cfg_attr(feature = "openapi", schema($($schema)*))])? $field_vis $field: $type),*
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                #[derive(serde::Deserialize)]
                $($unknown_fields)*
                struct Fields {
                    $($(#[$field_attr])* $field: $type),*
                }

                let Fields { $($field),* } = $crate::wire::deserialize_object(deserializer)?;
                Ok(Self { $($field),* })
            }
        }
    };
}

pub(crate) use wire_struct;

/// Utoipa derives the variants and their tags but leaves variant objects open.
/// Close those objects after deriving the shape from the Serde fields.
macro_rules! strict_enum {
    (
        // Forward the tag as a token so Utoipa can read a literal directly.
        tag = $tag:tt,
        decode = $decode:ident,
        $(#[$attr:meta])*
        $vis:vis enum $name:ident {
            $($variant:ident { $($(#[$field_attr:meta])* $field:ident: $type:ty),* $(,)? }),+ $(,)?
        }
    ) => {
        $(#[$attr])*
        #[derive(serde::Serialize)]
        #[serde(tag = $tag, rename_all = "snake_case", deny_unknown_fields)]
        $vis enum $name {
            $($variant { $($(#[$field_attr])* $field: $type),* }),+
        }

        const _: () = {
            #[derive(serde::Deserialize)]
            #[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
            #[serde(tag = $tag, rename_all = "snake_case", deny_unknown_fields)]
            #[allow(dead_code, clippy::large_enum_variant)]
            enum Wire {
                $($variant { $($(#[$field_attr])* $field: $type),* }),+
            }

            $crate::wire::strict_enum!(@decode $decode $name { $($variant { $($field),* }),+ });

            #[cfg(feature = "openapi")]
            impl utoipa::PartialSchema for $name {
                fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
                    $crate::wire::schema::close_tagged_variants(<Wire as utoipa::PartialSchema>::schema())
                }
            }

            #[cfg(feature = "openapi")]
            impl utoipa::ToSchema for $name {
                fn schemas(schemas: &mut Vec<(String, utoipa::openapi::RefOr<utoipa::openapi::schema::Schema>)>) {
                    <Wire as utoipa::ToSchema>::schemas(schemas);
                }
            }
        };
    };

    (@decode custom $name:ident { $($fields:tt)* }) => {};

    (@decode object $name:ident { $($variant:ident { $($field:ident),* }),+ }) => {
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let wire: Wire = $crate::wire::deserialize_object(deserializer)?;
                Ok(match wire {
                    $(Wire::$variant { $($field),* } => Self::$variant { $($field),* }),+
                })
            }
        }
    };
}

pub(crate) use strict_enum;

#[cfg(feature = "openapi")]
pub(crate) mod schema {
    use utoipa::openapi::{
        RefOr,
        schema::{AdditionalProperties, ObjectBuilder, Schema, Type},
    };

    pub(crate) fn closed_object() -> ObjectBuilder {
        ObjectBuilder::new().additional_properties(Some(AdditionalProperties::FreeForm(false)))
    }

    pub(crate) fn string_tag(tag: &str) -> ObjectBuilder {
        ObjectBuilder::new()
            .schema_type(Type::String)
            .enum_values(Some([tag]))
    }

    pub(crate) fn close_tagged_variants(mut schema: RefOr<Schema>) -> RefOr<Schema> {
        if let RefOr::T(Schema::OneOf(variants)) = &mut schema {
            for variant in &mut variants.items {
                if let RefOr::T(Schema::Object(object)) = variant {
                    object.additional_properties =
                        Some(Box::new(AdditionalProperties::FreeForm(false)));
                }
            }
        }
        schema
    }
}

#[derive(Debug)]
pub(crate) enum BoundedJsonError {
    TooLarge,
    Serialization,
}

/// Count the serialized bytes without retaining their contents.
pub(crate) fn bounded_json_len(
    limit: usize,
    serialize: impl FnOnce(&mut ByteCounter) -> serde_json::Result<()>,
) -> Result<usize, BoundedJsonError> {
    let mut counter = ByteCounter {
        remaining: limit,
        overflow: false,
    };
    serialize(&mut counter).map_err(|_| {
        if counter.overflow {
            BoundedJsonError::TooLarge
        } else {
            BoundedJsonError::Serialization
        }
    })?;
    Ok(limit - counter.remaining)
}

pub(crate) struct ByteCounter {
    remaining: usize,
    overflow: bool,
}

impl std::io::Write for ByteCounter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let Some(remaining) = self.remaining.checked_sub(bytes.len()) else {
            self.overflow = true;
            return Err(std::io::ErrorKind::FileTooLarge.into());
        };
        self.remaining = remaining;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Refuse a write before it could grow the preallocated buffer.
pub(crate) struct BoundedBuffer<'a> {
    bytes: &'a mut Vec<u8>,
    limit: usize,
}

impl<'a> BoundedBuffer<'a> {
    pub(crate) fn new(bytes: &'a mut Vec<u8>, limit: usize) -> Self {
        let limit = limit.min(bytes.capacity());
        Self { bytes, limit }
    }
}

impl std::io::Write for BoundedBuffer<'_> {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        if input.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(std::io::ErrorKind::FileTooLarge.into());
        }
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
