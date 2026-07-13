//! Installed-process Claude adapter lifecycle using public-surface stand-ins.

#[cfg(unix)]
mod unix {
    use sha2::{Digest as _, Sha256};
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};

    fn executable(path: &Path, body: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        fs::write(path, body)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        Ok(())
    }

    fn workspace() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("adapters/claude-code")
    }

    fn copy_tree(source: &Path, destination: &Path) -> Result<(), Box<dyn std::error::Error>> {
        fs::create_dir_all(destination)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let source = entry.path();
            let destination = destination.join(entry.file_name());
            let metadata = fs::symlink_metadata(&source)?;
            if metadata.file_type().is_symlink() {
                return Err("fixture package cannot contain symlinks".into());
            }
            if metadata.is_dir() {
                copy_tree(&source, &destination)?;
            } else if metadata.is_file() {
                fs::copy(&source, &destination)?;
            } else {
                return Err("fixture package contains a special file".into());
            }
        }
        Ok(())
    }

    fn regenerate_manifest(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
        fn visit(
            root: &Path,
            directory: &Path,
            files: &mut Vec<PathBuf>,
        ) -> Result<(), Box<dyn std::error::Error>> {
            for entry in fs::read_dir(directory)? {
                let entry = entry?;
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path)?;
                if metadata.file_type().is_symlink() {
                    return Err("fixture package cannot contain symlinks".into());
                }
                if metadata.is_dir() {
                    visit(root, &path, files)?;
                } else if metadata.is_file() && path != root.join("package-manifest.json") {
                    files.push(path);
                }
            }
            Ok(())
        }

        let mut files = Vec::new();
        visit(root, root, &mut files)?;
        files.sort_by_key(|path| {
            path.strip_prefix(root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/")
        });
        let entries = files
            .into_iter()
            .map(|path| {
                let bytes = fs::read(&path)?;
                let relative = path
                    .strip_prefix(root)?
                    .to_string_lossy()
                    .replace('\\', "/");
                Ok(serde_json::json!({
                    "path": relative,
                    "sha256": Sha256::digest(&bytes)
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>(),
                    "bytes": bytes.len()
                }))
            })
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
        fs::write(
            root.join("package-manifest.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "schema_version": "cigar.claude-code-package.v1",
                "files": entries
            }))?,
        )?;
        Ok(())
    }

    struct Fixture {
        directory: tempfile::TempDir,
        home: PathBuf,
        cigar_home: PathBuf,
        claude: PathBuf,
        component: PathBuf,
        log: PathBuf,
        provider_sentinel: Vec<u8>,
        catalog_sentinel: PathBuf,
    }

    impl Fixture {
        fn new(version: &str) -> Result<Self, Box<dyn std::error::Error>> {
            let directory = tempfile::tempdir()?;
            let home = directory.path().join("home with spaces");
            let cigar_home = directory.path().join("cigar state");
            let bin = directory.path().join("bin with spaces");
            fs::create_dir_all(home.join(".claude"))?;
            fs::create_dir_all(&cigar_home)?;
            fs::create_dir_all(&bin)?;
            let provider_sentinel =
                b"{\n  \"unrelated\": [\"byte preserving\", \"honeybee\"]\n}\n".to_vec();
            fs::write(home.join(".claude/settings.json"), &provider_sentinel)?;
            let catalog_sentinel = cigar_home.join("catalog-portable.sentinel");
            fs::write(&catalog_sentinel, b"portable catalog bytes\n")?;
            let log = directory.path().join("claude-invocations.log");
            let claude = bin.join("claude-fixture");
            let script = format!(
                "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$*\" >> \"$CIGAR_TEST_CLAUDE_LOG\"\nif [ \"$#\" -gt 0 ] && [ \"$1\" = \"--version\" ]; then printf '%s (Claude Code)\\n' '{}'; fi\n",
                version
            );
            executable(&claude, script.as_bytes())?;
            let component = bin.join("component-fixture");
            executable(
                &component,
                b"#!/bin/sh\nset -eu\nprintf '{\"ok\":true}\\n'\n",
            )?;
            Ok(Self {
                directory,
                home,
                cigar_home,
                claude,
                component,
                log,
                provider_sentinel,
                catalog_sentinel,
            })
        }

        fn run(&self, arguments: &[&str]) -> Result<Output, Box<dyn std::error::Error>> {
            self.run_with_source(arguments, &workspace())
        }

        fn run_with_source(
            &self,
            arguments: &[&str],
            source: &Path,
        ) -> Result<Output, Box<dyn std::error::Error>> {
            Ok(Command::new(env!("CARGO_BIN_EXE_cigar"))
                .args(arguments)
                .env("HOME", &self.home)
                .env("CIGAR_HOME", &self.cigar_home)
                .env("CIGAR_CLAUDE_PLUGIN_SOURCE", source)
                .env("CIGAR_TEST_PLUGIN_SOURCE", source)
                .env("CIGAR_CLAUDE_BINARY", &self.claude)
                .env("CIGAR_MCP_BINARY", &self.component)
                .env("CIGAR_CLAUDE_HOOK_BINARY", &self.component)
                .env("CIGAR_CLAUDE_DAEMON_CHECK_BINARY", &self.component)
                .env("CIGAR_TEST_CLAUDE_LOG", &self.log)
                .output()?)
        }

        fn package_copy(&self, name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
            let destination = self.directory.path().join(name);
            copy_tree(&workspace(), &destination)?;
            Ok(destination)
        }

        fn mutate_source_during_last_handshake(&self) -> Result<(), Box<dyn std::error::Error>> {
            executable(
                &self.component,
                br##"#!/bin/sh
set -eu
if [ "$#" -gt 0 ] && [ "$1" = "schema-noop" ]; then
  printf '%s\n' '{"mcpServers":{"cigar":{"command":"post-validation-attacker-command","args":["serve"],"env":{"CIGAR_CLAUDE_PLUGIN_ROOT":"${CLAUDE_PLUGIN_ROOT}","CIGAR_CLAUDE_PLUGIN_DATA":"${CLAUDE_PLUGIN_DATA}"}}}}' > "$CIGAR_TEST_PLUGIN_SOURCE/.mcp.json"
fi
printf '{"ok":true}\n'
"##,
            )
        }

        fn assert_host_bytes_unchanged(&self) -> Result<(), Box<dyn std::error::Error>> {
            assert_eq!(
                fs::read(self.home.join(".claude/settings.json"))?,
                self.provider_sentinel
            );
            assert_eq!(
                fs::read(&self.catalog_sentinel)?,
                b"portable catalog bytes\n"
            );
            Ok(())
        }
    }

    #[test]
    fn fake_home_install_preview_doctor_and_byte_preserving_uninstall()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new("2.1.207")?;
        let preview = fixture.run(&[
            "plugin",
            "install",
            "claude-code",
            "--dry-run",
            "--output",
            "json",
            "--deadline",
            "10s",
        ])?;
        assert!(
            preview.status.success(),
            "{}",
            String::from_utf8_lossy(&preview.stderr)
        );
        let preview: serde_json::Value = serde_json::from_slice(&preview.stdout)?;
        assert_eq!(preview.pointer("/result/planned"), Some(&true.into()));
        assert!(!fixture.cigar_home.join("claude-code/install.json").exists());
        fixture.assert_host_bytes_unchanged()?;

        let install = fixture.run(&[
            "plugin",
            "install",
            "claude-code",
            "--yes",
            "--output",
            "json",
            "--deadline",
            "10s",
        ])?;
        assert!(
            install.status.success(),
            "{}",
            String::from_utf8_lossy(&install.stderr)
        );
        assert!(
            fixture
                .cigar_home
                .join("claude-code/install.json")
                .is_file()
        );
        fixture.assert_host_bytes_unchanged()?;

        let doctor = fixture.run(&[
            "plugin",
            "doctor",
            "claude-code",
            "--output",
            "json",
            "--deadline",
            "10s",
        ])?;
        assert!(doctor.status.success());
        let doctor: serde_json::Value = serde_json::from_slice(&doctor.stdout)?;
        assert_eq!(doctor.pointer("/result/installed"), Some(&true.into()));
        assert_eq!(
            doctor.pointer("/result/private_provider_files"),
            Some(&false.into())
        );

        let uninstall = fixture.run(&[
            "plugin",
            "uninstall",
            "claude-code",
            "--yes",
            "--output",
            "json",
            "--deadline",
            "10s",
        ])?;
        assert!(
            uninstall.status.success(),
            "{}",
            String::from_utf8_lossy(&uninstall.stderr)
        );
        assert!(!fixture.cigar_home.join("claude-code/install.json").exists());
        fixture.assert_host_bytes_unchanged()?;
        let log = fs::read_to_string(&fixture.log)?;
        for public_call in [
            "plugin validate",
            "plugin marketplace add",
            "plugin install cigar@cigar-local --scope user",
            "plugin uninstall cigar@cigar-local --scope user",
            "plugin marketplace remove cigar-local",
        ] {
            assert!(log.contains(public_call), "missing {public_call}: {log}");
        }
        Ok(())
    }

    #[test]
    fn unsupported_claude_version_changes_nothing_and_reports_stable_error()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new("2.0.67")?;
        let output = fixture.run(&[
            "plugin",
            "install",
            "claude-code",
            "--dry-run",
            "--output",
            "json",
        ])?;
        assert_eq!(output.status.code(), Some(69));
        let failure: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(
            failure
                .pointer("/error/code")
                .and_then(|value| value.as_str()),
            Some("CLI_PLUGIN_INCOMPATIBLE")
        );
        assert!(!fixture.cigar_home.join("claude-code").exists());
        fixture.assert_host_bytes_unchanged()?;
        assert_eq!(fs::read_to_string(&fixture.log)?.lines().count(), 1);
        Ok(())
    }

    #[test]
    fn self_rewritten_package_manifest_cannot_authorize_a_different_mcp_command()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new("2.1.207")?;
        let source = fixture.package_copy("mutable-mcp-package")?;
        let path = source.join(".mcp.json");
        let mut mcp: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
        *mcp.pointer_mut("/mcpServers/cigar/command")
            .ok_or("MCP command")? = "attacker-controlled-mcp".into();
        fs::write(&path, serde_json::to_vec_pretty(&mcp)?)?;
        regenerate_manifest(&source)?;

        let output = fixture.run_with_source(
            &[
                "plugin",
                "install",
                "claude-code",
                "--dry-run",
                "--output",
                "json",
                "--deadline",
                "10s",
            ],
            &source,
        )?;
        assert_eq!(output.status.code(), Some(65));
        let failure: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(
            failure
                .pointer("/error/code")
                .and_then(serde_json::Value::as_str),
            Some("CLI_PLUGIN_INVALID")
        );
        Ok(())
    }

    #[test]
    fn self_rewritten_package_manifest_cannot_authorize_a_different_hook_command()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new("2.1.207")?;
        let source = fixture.package_copy("mutable-hook-package")?;
        let path = source.join("hooks/hooks.json");
        let mut hooks: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
        *hooks
            .pointer_mut("/hooks/SessionStart/0/hooks/0/command")
            .ok_or("hook command")? = "attacker-controlled-hook".into();
        fs::write(&path, serde_json::to_vec_pretty(&hooks)?)?;
        regenerate_manifest(&source)?;

        let output = fixture.run_with_source(
            &[
                "plugin",
                "install",
                "claude-code",
                "--dry-run",
                "--output",
                "json",
                "--deadline",
                "10s",
            ],
            &source,
        )?;
        assert_eq!(output.status.code(), Some(65));
        let failure: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(
            failure
                .pointer("/error/code")
                .and_then(serde_json::Value::as_str),
            Some("CLI_PLUGIN_INVALID")
        );
        Ok(())
    }

    #[test]
    fn staged_plugin_uses_authenticated_bytes_when_source_changes_during_last_handshake()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new("2.1.207")?;
        let source = fixture.package_copy("source-mutated-after-validation")?;
        fixture.mutate_source_during_last_handshake()?;

        let output = fixture.run_with_source(
            &[
                "plugin",
                "install",
                "claude-code",
                "--yes",
                "--output",
                "json",
                "--deadline",
                "10s",
            ],
            &source,
        )?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let receipt: serde_json::Value = serde_json::from_slice(&fs::read(
            fixture.cigar_home.join("claude-code/install.json"),
        )?)?;
        let marketplace = receipt
            .get("marketplace_root")
            .and_then(serde_json::Value::as_str)
            .ok_or("marketplace root")?;
        let installed: serde_json::Value = serde_json::from_slice(&fs::read(
            Path::new(marketplace).join("plugins/cigar/.mcp.json"),
        )?)?;
        assert_eq!(
            installed.pointer("/mcpServers/cigar/command"),
            Some(&serde_json::Value::String("cigar-mcp".to_owned()))
        );
        Ok(())
    }
}
