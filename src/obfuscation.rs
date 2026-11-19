use rand::{Rng, RngCore, rngs::OsRng};
use tokio::time::{Duration, sleep};

/// Padding is *inside* the authenticated ciphertext and then inside TLS.
/// This alters record lengths, but is not a guarantee against traffic analysis.
pub fn pad_len(max: usize) -> usize {
    if max == 0 { 0 } else { rand::thread_rng().gen_range(0..=max) }
}
pub fn random_padding(len: usize) -> Vec<u8> {
    let mut padding = vec![0u8; len]; OsRng.fill_bytes(&mut padding); padding
}
pub async fn jitter(max_ms: u64) {
    if max_ms > 0 {
        let wait = rand::thread_rng().gen_range(0..=max_ms);
        sleep(Duration::from_millis(wait)).await;
    }
}
#[cfg(test)]
mod tests { use super::*;
    #[test] fn padding_is_bounded() { for _ in 0..128 { assert!(pad_len(64) <= 64); } assert_eq!(pad_len(0), 0); }
}
