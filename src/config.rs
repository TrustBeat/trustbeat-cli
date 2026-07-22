//! API key and endpoint resolution.
//!
//! Precedence, highest first:
//!   1. `--api-key` / `--api-url` flags
//!   2. `TRUSTBEAT_API_KEY` / `TRUSTBEAT_API_URL` environment variables
//!   3. `$TRUSTBEAT_CONFIG_HOME`, else `~/.config/trustbeat/credentials`
//!
//! `verify` never needs any of this — offline verification is the whole point.

use std::path::PathBuf;

pub const DEFAULT_API_URL: &str = "https://api.trustbeat.eu/v1";

pub fn config_path() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("TRUSTBEAT_CONFIG_HOME") {
        return Some(PathBuf::from(dir).join("credentials"));
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()?;
    Some(
        PathBuf::from(home)
            .join(".config")
            .join("trustbeat")
            .join("credentials"),
    )
}

/// Reads `key = value` lines, ignoring blanks and `#` comments.
fn read_config_value(key: &str) -> Option<String> {
    let path = config_path()?;
    let contents = std::fs::read_to_string(path).ok()?;
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == key {
                return Some(v.trim().trim_matches('"').to_string());
            }
        }
    }
    None
}

pub fn resolve_api_key(flag: Option<String>) -> Result<String, String> {
    flag.filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var("TRUSTBEAT_API_KEY")
                .ok()
                .filter(|s| !s.is_empty())
        })
        .or_else(|| read_config_value("api_key"))
        .ok_or_else(|| {
            let where_to_put_it = config_path()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "~/.config/trustbeat/credentials".into());
            format!(
                "no API key found.\n\n\
                 Set one of:\n  \
                 export TRUSTBEAT_API_KEY=tb_live_...\n  \
                 trustbeat anchor --api-key tb_live_... <file>\n  \
                 echo 'api_key = tb_live_...' > {where_to_put_it}\n\n\
                 Get a key at https://trustbeat.eu/register\n\
                 (`trustbeat verify` needs no key — it works entirely offline.)"
            )
        })
}

pub fn resolve_api_url(flag: Option<String>) -> String {
    flag.filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var("TRUSTBEAT_API_URL")
                .ok()
                .filter(|s| !s.is_empty())
        })
        .or_else(|| read_config_value("api_url"))
        .unwrap_or_else(|| DEFAULT_API_URL.to_string())
        .trim_end_matches('/')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Env mutation is process-global; serialise these tests behind one mutex.
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct EnvGuard(Vec<(&'static str, Option<String>)>);

    impl EnvGuard {
        fn set(vars: &[(&'static str, Option<&str>)]) -> Self {
            let saved = vars
                .iter()
                .map(|(k, _)| (*k, std::env::var(k).ok()))
                .collect();
            for (k, v) in vars {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
            EnvGuard(saved)
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (k, v) in &self.0 {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    fn temp_config(contents: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "trustbeat-cfg-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("credentials"), contents).unwrap();
        dir
    }

    #[test]
    fn flag_beats_environment() {
        let _g = LOCK.lock().unwrap();
        let _e = EnvGuard::set(&[
            ("TRUSTBEAT_API_KEY", Some("from_env")),
            ("TRUSTBEAT_CONFIG_HOME", None),
        ]);
        assert_eq!(
            resolve_api_key(Some("from_flag".into())).unwrap(),
            "from_flag"
        );
    }

    #[test]
    fn environment_beats_config_file() {
        let _g = LOCK.lock().unwrap();
        let dir = temp_config("api_key = from_file\n");
        let _e = EnvGuard::set(&[
            ("TRUSTBEAT_API_KEY", Some("from_env")),
            ("TRUSTBEAT_CONFIG_HOME", Some(dir.to_str().unwrap())),
        ]);
        assert_eq!(resolve_api_key(None).unwrap(), "from_env");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn falls_back_to_the_config_file() {
        let _g = LOCK.lock().unwrap();
        let dir =
            temp_config("# comment\n\napi_key = \"from_file\"\napi_url = https://x.test/v1\n");
        let _e = EnvGuard::set(&[
            ("TRUSTBEAT_API_KEY", None),
            ("TRUSTBEAT_API_URL", None),
            ("TRUSTBEAT_CONFIG_HOME", Some(dir.to_str().unwrap())),
        ]);
        assert_eq!(resolve_api_key(None).unwrap(), "from_file");
        assert_eq!(resolve_api_url(None), "https://x.test/v1");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_missing_key_explains_how_to_set_one() {
        let _g = LOCK.lock().unwrap();
        let dir = temp_config("");
        let _e = EnvGuard::set(&[
            ("TRUSTBEAT_API_KEY", None),
            ("TRUSTBEAT_CONFIG_HOME", Some(dir.to_str().unwrap())),
        ]);
        let err = resolve_api_key(None).unwrap_err();
        assert!(err.contains("TRUSTBEAT_API_KEY"));
        assert!(err.contains("verify"), "should mention verify needs no key");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn empty_values_are_treated_as_absent() {
        let _g = LOCK.lock().unwrap();
        let dir = temp_config("");
        let _e = EnvGuard::set(&[
            ("TRUSTBEAT_API_KEY", Some("")),
            ("TRUSTBEAT_CONFIG_HOME", Some(dir.to_str().unwrap())),
        ]);
        assert!(resolve_api_key(Some(String::new())).is_err());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn url_defaults_to_production_and_strips_trailing_slash() {
        let _g = LOCK.lock().unwrap();
        let dir = temp_config("");
        let _e = EnvGuard::set(&[
            ("TRUSTBEAT_API_URL", None),
            ("TRUSTBEAT_CONFIG_HOME", Some(dir.to_str().unwrap())),
        ]);
        assert_eq!(resolve_api_url(None), DEFAULT_API_URL);
        assert_eq!(
            resolve_api_url(Some("https://x.test/v1/".into())),
            "https://x.test/v1"
        );
        std::fs::remove_dir_all(dir).ok();
    }
}
