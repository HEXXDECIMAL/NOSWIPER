fn matches_pattern(pattern: &str, text: &str) -> bool {
    // Handle wildcards
    if pattern.contains('*') {
        // Convert pattern to regex-like matching
        let parts: Vec<&str> = pattern.split('*').collect();

        if parts.is_empty() {
            return true;
        }

        let mut pos = 0;
        for (i, part) in parts.iter().enumerate() {
            if part.is_empty() {
                continue;
            }

            // First part must match at beginning
            if i == 0 && !pattern.starts_with('*') {
                if !text.starts_with(part) {
                    return false;
                }
                pos = part.len();
            }
            // Last part must match at end
            else if i == parts.len() - 1 && !pattern.ends_with('*') {
                return text.ends_with(part);
            }
            // Middle parts can match anywhere after current position
            else if let Some(idx) = text[pos..].find(part) {
                pos += idx + part.len();
            } else {
                return false;
            }
        }
        true
    } else {
        pattern == text
    }
}

fn main() {
    let pattern = "/Applications/*.app/Contents/MacOS/*";
    let spotify_path = "/Applications/Spotify.app/Contents/MacOS/Spotify";

    println!("Pattern: {}", pattern);
    println!("Path: {}", spotify_path);
    println!("Matches: {}", matches_pattern(pattern, spotify_path));

    // Also test the keychain rule pattern
    let pattern2 = "/Applications/*/Contents/MacOS/*";
    println!("\nPattern: {}", pattern2);
    println!("Path: {}", spotify_path);
    println!("Matches: {}", matches_pattern(pattern2, spotify_path));
}
