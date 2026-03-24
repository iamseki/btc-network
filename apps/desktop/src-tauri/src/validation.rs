use crate::error::DesktopError;

const MAX_NODE_LENGTH: usize = 255;
const MAX_OPERATION_ID_LENGTH: usize = 128;
const BLOCK_HASH_HEX_LENGTH: usize = 64;

pub fn validate_node(node: &str) -> Result<(), DesktopError> {
    let trimmed = node.trim();
    if trimmed.is_empty() {
        return Err(DesktopError::invalid_request("node must not be empty"));
    }

    if trimmed.len() > MAX_NODE_LENGTH {
        return Err(DesktopError::invalid_request("node is too long"));
    }

    let Some((host, port)) = split_host_port(trimmed) else {
        return Err(DesktopError::invalid_request(
            "node must be a valid host:port",
        ));
    };

    if host.is_empty()
        || port.is_empty()
        || host.chars().any(char::is_whitespace)
        || port.chars().any(char::is_whitespace)
    {
        return Err(DesktopError::invalid_request(
            "node must be a valid host:port",
        ));
    }

    port.parse::<u16>()
        .map(|_| ())
        .map_err(|_| DesktopError::invalid_request("node must be a valid host:port"))
}

pub fn validate_operation_id(operation_id: &str) -> Result<(), DesktopError> {
    if operation_id.is_empty() {
        return Err(DesktopError::invalid_request(
            "operationId must not be empty",
        ));
    }

    if operation_id.len() > MAX_OPERATION_ID_LENGTH {
        return Err(DesktopError::invalid_request("operationId is too long"));
    }

    if operation_id.chars().all(is_operation_id_char) {
        Ok(())
    } else {
        Err(DesktopError::invalid_request(
            "operationId contains invalid characters",
        ))
    }
}

pub fn validate_block_hash(hash: &str) -> Result<(), DesktopError> {
    if hash.len() != BLOCK_HASH_HEX_LENGTH {
        return Err(DesktopError::invalid_request(
            "hash must be a 64-character hex string",
        ));
    }

    if hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(DesktopError::invalid_request(
            "hash must be a 64-character hex string",
        ))
    }
}

fn is_operation_id_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.')
}

fn split_host_port(node: &str) -> Option<(&str, &str)> {
    if let Some(rest) = node.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let port = rest[end + 1..].strip_prefix(':')?;
        return Some((host, port));
    }

    let (host, port) = node.rsplit_once(':')?;
    if host.contains(':') {
        return None;
    }

    Some((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_block_hash_rejects_non_hex_input() {
        let err = validate_block_hash("z".repeat(64).as_str()).expect_err("invalid hash");
        assert_eq!(err.code, "invalid_request");
    }

    #[test]
    fn validate_operation_id_rejects_spaces() {
        let err = validate_operation_id("bad id").expect_err("invalid operation id");
        assert_eq!(err.code, "invalid_request");
    }

    #[test]
    fn validate_node_rejects_empty_input() {
        let err = validate_node("   ").expect_err("invalid node");
        assert_eq!(err.code, "invalid_request");
    }

    #[test]
    fn validate_node_accepts_hostname_without_resolution() {
        validate_node("seed.bitnodes.io:8333").expect("valid hostname");
    }

    #[test]
    fn validate_node_accepts_bracketed_ipv6() {
        validate_node("[2001:db8::1]:8333").expect("valid ipv6");
    }
}
