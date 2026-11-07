use crate::ConfigError;

pub const MAX_INTERFACE_NAME: usize = 15;

pub fn validate_interface_name(field: &str, name: &str, max_len: usize) -> Result<(), ConfigError> {
    let valid_chars = name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'));

    if name.is_empty() || name.len() > max_len || !valid_chars {
        return Err(ConfigError::invalid(
            field,
            format!("\"{name}\" must be 1-{max_len} letters, digits, '-' or '_'"),
        ));
    }

    Ok(())
}
