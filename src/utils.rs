use anyhow::Result;
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use tokio::task;

pub fn is_valid_email(email: &str) -> bool {
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }

    let (local, domain) = (parts[0], parts[1]);

    if local.is_empty()
        || local.len() > 64
        || domain.is_empty()
        || domain.len() > 255
        || !domain.contains('.')
    {
        return false;
    }

    if !local
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || ".!#$%&'*+/=?^_`{|}~-".contains(c))
    {
        return false;
    }

    for label in domain.split('.') {
        if label.is_empty() {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }

    true
}

pub async fn hash_password(password: String) -> Result<String> {
    let hash = task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);

        let argon2 = Argon2::default();

        argon2
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))
    })
    .await??;

    Ok(hash)
}

pub async fn verify_password(password: String, hash: String) -> Result<bool> {
    let is_valid = task::spawn_blocking(move || -> Result<bool> {
        let parsed_hash =
            PasswordHash::new(&hash).map_err(|e| anyhow::anyhow!("Invalid hash format: {}", e))?;

        let argon2 = Argon2::default();

        Ok(argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    })
    .await??;

    Ok(is_valid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_simple_email() {
        assert!(is_valid_email("user@example.com"));
        assert!(is_valid_email("test@test.org"));
        assert!(is_valid_email("admin@domain.co.uk"));
    }

    #[test]
    fn test_valid_email_with_numbers() {
        assert!(is_valid_email("user123@example.com"));
        assert!(is_valid_email("test456@test789.org"));
    }

    #[test]
    fn test_valid_email_with_special_chars() {
        assert!(is_valid_email("user.name@example.com"));
        assert!(is_valid_email("user+tag@example.com"));
        assert!(is_valid_email("user_name@example.com"));
        assert!(is_valid_email("user-name@example.com"));
        assert!(is_valid_email("user!name@example.com"));
        assert!(is_valid_email("user#name@example.com"));
        assert!(is_valid_email("user$name@example.com"));
        assert!(is_valid_email("user%name@example.com"));
        assert!(is_valid_email("user&name@example.com"));
        assert!(is_valid_email("user'name@example.com"));
        assert!(is_valid_email("user*name@example.com"));
        assert!(is_valid_email("user/name@example.com"));
        assert!(is_valid_email("user=name@example.com"));
        assert!(is_valid_email("user?name@example.com"));
        assert!(is_valid_email("user^name@example.com"));
        assert!(is_valid_email("user`name@example.com"));
        assert!(is_valid_email("user{name@example.com"));
        assert!(is_valid_email("user|name@example.com"));
        assert!(is_valid_email("user}name@example.com"));
        assert!(is_valid_email("user~name@example.com"));
    }

    #[test]
    fn test_invalid_no_at_symbol() {
        assert!(!is_valid_email("userexample.com"));
        assert!(!is_valid_email("user.example.com"));
    }

    #[test]
    fn test_invalid_multiple_at_symbols() {
        assert!(!is_valid_email("user@exam@ple.com"));
        assert!(!is_valid_email("@user@example.com"));
    }

    #[test]
    fn test_invalid_empty_local_part() {
        assert!(!is_valid_email("@example.com"));
    }

    #[test]
    fn test_invalid_empty_domain() {
        assert!(!is_valid_email("user@"));
    }

    #[test]
    fn test_invalid_no_dot_in_domain() {
        assert!(!is_valid_email("user@example"));
        assert!(!is_valid_email("user@examplecom"));
    }

    #[test]
    fn test_invalid_domain_too_long() {
        let long_domain = "a".repeat(256);
        let email = format!("user@{}.com", long_domain);
        assert!(!is_valid_email(&email));
    }

    #[test]
    fn test_valid_domain_max_length() {
        let domain = "a".repeat(250);
        let email = format!("user@{}.com", domain);
        assert!(is_valid_email(&email));
    }

    #[test]
    fn test_invalid_domain_starts_with_hyphen() {
        assert!(!is_valid_email("user@-example.com"));
    }

    #[test]
    fn test_invalid_domain_ends_with_hyphen() {
        assert!(!is_valid_email("user@example-.com"));
        assert!(!is_valid_email("user@example.com-"));
    }

    #[test]
    fn test_valid_domain_with_hyphen() {
        assert!(is_valid_email("user@ex-ample.com"));
        assert!(is_valid_email("user@my-domain.co.uk"));
    }

    #[test]
    fn test_invalid_local_with_disallowed_chars() {
        assert!(!is_valid_email("user name@example.com"));
        assert!(!is_valid_email("user@name@example.com"));
        assert!(!is_valid_email("user[name@example.com"));
        assert!(!is_valid_email("user]name@example.com"));
        assert!(!is_valid_email("user(name@example.com"));
        assert!(!is_valid_email("user)name@example.com"));
    }

    #[test]
    fn test_empty_string() {
        assert!(!is_valid_email(""));
    }

    #[test]
    fn test_only_at_symbol() {
        assert!(!is_valid_email("@"));
    }
}
