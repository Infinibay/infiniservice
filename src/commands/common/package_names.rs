//! Package name normalization utilities
//!
//! This module provides functions for generating possible package names from
//! human-readable application names. Different package managers have different
//! naming conventions, and this module consolidates the normalization logic.
//!
//! # Examples
//!
//! ```rust,ignore
//! use crate::commands::common::package_names::generate_debian_package_names;
//!
//! let names = generate_debian_package_names("Firefox Browser");
//! // Returns: ["firefox-browser", "firefoxbrowser", "firefox browser",
//! //           "libfirefox-browser", "firefox-browser-dev", "firefox-browser-common"]
//! ```

/// Normalize an application name into common package name variations.
///
/// This generates basic variations that work across most package managers:
/// - Lowercase with spaces replaced by hyphens
/// - Lowercase with spaces removed
/// - Lowercase as-is
///
/// # Arguments
///
/// * `app_name` - The human-readable application name
///
/// # Returns
///
/// A vector of normalized package name variations
///
/// # Example
///
/// ```rust,ignore
/// let names = normalize_package_name("Firefox Browser");
/// assert!(names.contains(&"firefox-browser".to_string()));
/// assert!(names.contains(&"firefoxbrowser".to_string()));
/// assert!(names.contains(&"firefox browser".to_string()));
/// ```
pub fn normalize_package_name(app_name: &str) -> Vec<String> {
    let mut names = Vec::new();

    // Normalize: lowercase, spaces → hyphens, underscores → hyphens
    let normalized = app_name
        .to_lowercase()
        .replace(' ', "-")
        .replace('_', "-");

    names.push(normalized);

    // Variation: lowercase with spaces removed
    names.push(app_name.to_lowercase().replace(' ', ""));

    // Variation: lowercase as-is
    names.push(app_name.to_lowercase());

    names
}

/// Generate Debian/APT-specific package name variations.
///
/// Debian packages often have prefixes like `lib` and suffixes like `-dev`,
/// `-common`. This function generates all common variations for APT lookups.
///
/// # Arguments
///
/// * `app_name` - The human-readable application name
///
/// # Returns
///
/// A vector of possible Debian package names
///
/// # Example
///
/// ```rust,ignore
/// let names = generate_debian_package_names("Firefox Browser");
/// // Includes: "firefox-browser", "firefoxbrowser", "firefox browser",
/// //           "libfirefox-browser", "firefox-browser-dev", "firefox-browser-common"
/// ```
pub fn generate_debian_package_names(app_name: &str) -> Vec<String> {
    let mut names = normalize_package_name(app_name);

    let normalized = app_name
        .to_lowercase()
        .replace(' ', "-")
        .replace('_', "-");

    // Add Debian-specific patterns
    if !normalized.is_empty() {
        // Library prefix (common for development packages)
        names.push(format!("lib{}", normalized));

        // Development package suffix
        names.push(format!("{}-dev", normalized));

        // Common package suffix (shared files)
        names.push(format!("{}-common", normalized));
    }

    names
}

/// Generate RPM-specific package name variations.
///
/// RPM packages typically use simpler naming conventions compared to Debian.
/// This function generates the basic variations suitable for dnf/yum lookups.
///
/// # Arguments
///
/// * `app_name` - The human-readable application name
///
/// # Returns
///
/// A vector of possible RPM package names
///
/// # Example
///
/// ```rust,ignore
/// let names = generate_rpm_package_names("Firefox Browser");
/// // Includes: "firefox-browser", "firefoxbrowser", "firefox browser"
/// ```
pub fn generate_rpm_package_names(app_name: &str) -> Vec<String> {
    // RPM uses simpler naming, just the base variations
    normalize_package_name(app_name)
}

/// Generate package names for Snap.
///
/// Snap packages use simple, lowercase names. This function generates
/// variations to improve matching for apps with display names differing
/// from snap IDs.
///
/// # Arguments
///
/// * `app_name` - The human-readable application name
///
/// # Returns
///
/// A vector with snap-compatible package name variations
///
/// # Example
///
/// ```rust,ignore
/// let names = generate_snap_package_names("Firefox Browser");
/// // Returns: ["firefox-browser", "firefoxbrowser", "firefox browser", "firefox"]
/// ```
pub fn generate_snap_package_names(app_name: &str) -> Vec<String> {
    let mut names = Vec::new();
    let lower = app_name.to_lowercase();

    // With hyphens (common snap naming convention)
    names.push(lower.replace(' ', "-").replace('_', "-"));

    // Without spaces
    names.push(lower.replace(' ', "").replace('_', ""));

    // Original lowercase
    names.push(lower.clone());

    // First word only (common for apps like "Firefox Browser" -> "firefox")
    if let Some(first_word) = lower.split_whitespace().next() {
        if !names.contains(&first_word.to_string()) {
            names.push(first_word.to_string());
        }
    }

    names
}

/// Generate simple package name for Flatpak.
///
/// Flatpak uses app IDs (e.g., `com.visualstudio.code`). When searching by
/// application name, we just use the lowercase name for matching.
///
/// # Arguments
///
/// * `app_name` - The human-readable application name
///
/// # Returns
///
/// A vector with the lowercase package name
pub fn generate_flatpak_package_names(app_name: &str) -> Vec<String> {
    vec![app_name.to_lowercase()]
}

/// Generate Windows-specific package name variations.
///
/// Windows applications often have prefixes like "Microsoft", "Google", "Adobe"
/// and suffixes like "Browser", "App". This function generates variations
/// suitable for WinGet and Windows Store lookups.
///
/// # Arguments
///
/// * `app_name` - The human-readable application name
///
/// # Returns
///
/// A vector of possible Windows package names
///
/// # Example
///
/// ```rust,ignore
/// let names = generate_windows_package_names("Google Chrome");
/// // Includes: "google chrome", "googlechrome", "chrome", "google-chrome"
/// ```
pub fn generate_windows_package_names(app_name: &str) -> Vec<String> {
    let mut names = Vec::new();
    let lower = app_name.to_lowercase();

    // Original lowercase
    names.push(lower.clone());

    // Without spaces
    names.push(lower.replace(' ', ""));

    // With hyphens
    names.push(lower.replace(' ', "-"));

    // Remove common prefixes (Microsoft, Google, Adobe, Mozilla)
    let clean_name = lower
        .replace("microsoft ", "")
        .replace("google ", "")
        .replace("adobe ", "")
        .replace("mozilla ", "")
        .replace(" browser", "")
        .replace(" app", "");

    if !clean_name.is_empty() && clean_name != lower {
        names.push(clean_name.clone());
        names.push(clean_name.replace(' ', ""));
        names.push(clean_name.replace(' ', "-"));
    }

    // Add specific common mappings
    match lower.as_str() {
        s if s.contains("chrome") => {
            if !names.contains(&"chrome".to_string()) {
                names.push("chrome".to_string());
            }
            if !names.contains(&"google chrome".to_string()) {
                names.push("google chrome".to_string());
            }
        }
        s if s.contains("firefox") => {
            if !names.contains(&"firefox".to_string()) {
                names.push("firefox".to_string());
            }
            if !names.contains(&"mozilla firefox".to_string()) {
                names.push("mozilla firefox".to_string());
            }
        }
        s if s.contains("edge") => {
            if !names.contains(&"edge".to_string()) {
                names.push("edge".to_string());
            }
            if !names.contains(&"microsoft edge".to_string()) {
                names.push("microsoft edge".to_string());
            }
        }
        s if s.contains("vscode") || s.contains("visual studio code") => {
            if !names.contains(&"code".to_string()) {
                names.push("code".to_string());
            }
            if !names.contains(&"vscode".to_string()) {
                names.push("vscode".to_string());
            }
        }
        _ => {}
    }

    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_package_name() {
        let names = normalize_package_name("Firefox Browser");

        assert!(names.contains(&"firefox-browser".to_string()));
        assert!(names.contains(&"firefoxbrowser".to_string()));
        assert!(names.contains(&"firefox browser".to_string()));
    }

    #[test]
    fn test_normalize_package_name_with_underscores() {
        let names = normalize_package_name("Visual_Studio_Code");

        assert!(names.contains(&"visual-studio-code".to_string()));
        assert!(names.contains(&"visual_studio_code".to_string()));
    }

    #[test]
    fn test_generate_debian_package_names() {
        let names = generate_debian_package_names("Firefox Browser");

        // Basic variations
        assert!(names.contains(&"firefox-browser".to_string()));
        assert!(names.contains(&"firefoxbrowser".to_string()));
        assert!(names.contains(&"firefox browser".to_string()));

        // Debian-specific patterns
        assert!(names.contains(&"libfirefox-browser".to_string()));
        assert!(names.contains(&"firefox-browser-dev".to_string()));
        assert!(names.contains(&"firefox-browser-common".to_string()));
    }

    #[test]
    fn test_generate_rpm_package_names() {
        let names = generate_rpm_package_names("Firefox Browser");

        assert!(names.contains(&"firefox-browser".to_string()));
        assert!(names.contains(&"firefoxbrowser".to_string()));
        assert!(names.contains(&"firefox browser".to_string()));

        // RPM doesn't add special prefixes/suffixes
        assert!(!names.contains(&"libfirefox-browser".to_string()));
    }

    #[test]
    fn test_generate_snap_package_names() {
        let names = generate_snap_package_names("Firefox Browser");

        // Snap generates multiple variations
        assert!(names.contains(&"firefox-browser".to_string()));
        assert!(names.contains(&"firefoxbrowser".to_string()));
        assert!(names.contains(&"firefox browser".to_string()));
        assert!(names.contains(&"firefox".to_string())); // First word only
    }

    #[test]
    fn test_generate_flatpak_package_names() {
        let names = generate_flatpak_package_names("Visual Studio Code");

        assert_eq!(names.len(), 1);
        assert_eq!(names[0], "visual studio code");
    }

    #[test]
    fn test_empty_app_name() {
        let names = generate_debian_package_names("");

        // Should not add prefixes/suffixes to empty string
        assert!(!names.contains(&"lib".to_string()));
        assert!(!names.contains(&"-dev".to_string()));
    }

    #[test]
    fn test_single_word_app_name() {
        let names = generate_debian_package_names("Firefox");

        assert!(names.contains(&"firefox".to_string()));
        assert!(names.contains(&"libfirefox".to_string()));
        assert!(names.contains(&"firefox-dev".to_string()));
        assert!(names.contains(&"firefox-common".to_string()));
    }

    #[test]
    fn test_generate_windows_package_names() {
        let names = generate_windows_package_names("Google Chrome");

        // Basic variations
        assert!(names.contains(&"google chrome".to_string()));
        assert!(names.contains(&"googlechrome".to_string()));
        assert!(names.contains(&"google-chrome".to_string()));

        // Without prefix
        assert!(names.contains(&"chrome".to_string()));
    }

    #[test]
    fn test_generate_windows_package_names_firefox() {
        let names = generate_windows_package_names("Mozilla Firefox");

        assert!(names.contains(&"mozilla firefox".to_string()));
        assert!(names.contains(&"firefox".to_string()));
    }

    #[test]
    fn test_generate_windows_package_names_vscode() {
        let names = generate_windows_package_names("Visual Studio Code");

        assert!(names.contains(&"visual studio code".to_string()));
        assert!(names.contains(&"code".to_string()));
        assert!(names.contains(&"vscode".to_string()));
    }
}
