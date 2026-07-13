//! Command-line entry point for the standalone CIGAR conformance runner.

use cigar_conformance::{
    AdapterTarget, IsolationMode, OverallResult, RunConfiguration, run_suite,
    validate_traceability, verify_result_file, write_json_artifact,
};
use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    match execute(env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn execute(arguments: Vec<String>) -> Result<(), String> {
    let (command, rest) = arguments.split_first().ok_or_else(|| usage().to_owned())?;
    match command.as_str() {
        "run" => run_command(rest),
        "verify" => verify_command(rest),
        "traceability" => traceability_command(rest),
        "help" | "--help" | "-h" => {
            println!("{}", usage());
            Ok(())
        }
        _ => Err(format!("unknown command `{command}`\n{}", usage())),
    }
}

fn run_command(arguments: &[String]) -> Result<(), String> {
    let options = Options::parse(arguments, &["--profile"])?;
    options.reject_unknown(&[
        "--profile",
        "--implementation",
        "--vectors",
        "--output",
        "--isolation",
        "--executable",
        "--sdk-adapter",
        "--endpoint",
        "--build-digest",
    ])?;
    let profiles = options
        .many
        .get("--profile")
        .cloned()
        .ok_or_else(|| "run requires at least one --profile".to_owned())?;
    let implementation = options.required("--implementation")?.to_owned();
    let vectors = PathBuf::from(
        options
            .one
            .get("--vectors")
            .map(String::as_str)
            .unwrap_or("conformance/vectors/v1"),
    );
    let output = PathBuf::from(
        options
            .one
            .get("--output")
            .map(String::as_str)
            .unwrap_or("reports/conformance-result.v1.json"),
    );
    let isolation = match options
        .one
        .get("--isolation")
        .map(String::as_str)
        .unwrap_or("strict")
    {
        "strict" => IsolationMode::Strict,
        "portable" => IsolationMode::Portable,
        _ => return Err("--isolation must be `strict` or `portable`".to_owned()),
    };
    let target = parse_target(&options)?;
    let configuration = RunConfiguration {
        profiles,
        target,
        implementation,
        remote_build_digest: options.one.get("--build-digest").cloned(),
        vectors,
        isolation,
    };
    let result = run_suite(&configuration)?;
    write_json_artifact(&output, &result)?;
    println!(
        "wrote {} cases for {} to {}",
        result.cases.len(),
        result.claimed_profiles.join(","),
        output.display()
    );
    if result.overall == OverallResult::Passed {
        Ok(())
    } else {
        Err("one or more required conformance cases failed".to_owned())
    }
}

fn verify_command(arguments: &[String]) -> Result<(), String> {
    let (result_path, options) = positional_and_options(arguments)?;
    options.reject_unknown(&["--vectors"])?;
    let vectors = options
        .one
        .get("--vectors")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("conformance/vectors/v1"));
    let result = verify_result_file(Path::new(result_path), &vectors)?;
    println!(
        "verified {} required cases; result digest {}",
        result.cases.len(),
        result.result_digest
    );
    Ok(())
}

fn traceability_command(arguments: &[String]) -> Result<(), String> {
    let options = Options::parse(arguments, &[])?;
    options.reject_unknown(&["--root", "--manifest", "--output"])?;
    let root = options
        .one
        .get("--root")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let manifest = options
        .one
        .get("--manifest")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("tests/invariants.yaml"));
    let result = validate_traceability(&root, &manifest)?;
    if let Some(output) = options.one.get("--output") {
        write_json_artifact(Path::new(output), &result)?;
    }
    println!(
        "validated {} normative requirements against {} active tests",
        result.requirement_count, result.test_count
    );
    Ok(())
}

fn parse_target(options: &Options) -> Result<AdapterTarget, String> {
    let mut targets = Vec::new();
    if let Some(path) = options.one.get("--executable") {
        targets.push(AdapterTarget::Executable(PathBuf::from(path)));
    }
    if let Some(path) = options.one.get("--sdk-adapter") {
        targets.push(AdapterTarget::SdkAdapter(PathBuf::from(path)));
    }
    if let Some(endpoint) = options.one.get("--endpoint") {
        let target = if let Some(path) = endpoint.strip_prefix("unix://") {
            if path.is_empty() {
                return Err("Unix endpoint path is empty".to_owned());
            }
            AdapterTarget::Unix(PathBuf::from(path))
        } else if endpoint.starts_with("http://") {
            AdapterTarget::Http(endpoint.clone())
        } else if endpoint.starts_with("grpc://") || endpoint.starts_with("grpcs://") {
            AdapterTarget::Grpc(endpoint.clone())
        } else {
            return Err("endpoint must use unix://, http://, grpc://, or grpcs://".to_owned());
        };
        targets.push(target);
    }
    if targets.len() != 1 {
        return Err("select exactly one of --executable, --sdk-adapter, or --endpoint".to_owned());
    }
    targets
        .pop()
        .ok_or_else(|| "adapter target disappeared".to_owned())
}

fn positional_and_options(arguments: &[String]) -> Result<(&str, Options), String> {
    let (first, rest) = arguments
        .split_first()
        .ok_or_else(|| "verify requires a result path".to_owned())?;
    if first.starts_with('-') {
        return Err("verify requires the result path before options".to_owned());
    }
    Ok((first, Options::parse(rest, &[])?))
}

struct Options {
    one: BTreeMap<String, String>,
    many: BTreeMap<String, Vec<String>>,
}

impl Options {
    fn parse(arguments: &[String], repeatable: &[&str]) -> Result<Self, String> {
        let mut one = BTreeMap::new();
        let mut many = BTreeMap::<String, Vec<String>>::new();
        let mut index = 0_usize;
        while index < arguments.len() {
            let key = arguments
                .get(index)
                .ok_or_else(|| "option index escaped argument vector".to_owned())?;
            if !key.starts_with("--") || key.len() <= 2 {
                return Err(format!("unexpected positional argument `{key}`"));
            }
            let value = arguments
                .get(index.saturating_add(1))
                .filter(|value| !value.starts_with("--"))
                .ok_or_else(|| format!("option `{key}` requires a value"))?;
            if repeatable.contains(&key.as_str()) {
                many.entry(key.clone()).or_default().push(value.clone());
            } else if one.insert(key.clone(), value.clone()).is_some() {
                return Err(format!("option `{key}` was provided more than once"));
            }
            index = index.saturating_add(2);
        }
        Ok(Self { one, many })
    }

    fn required(&self, name: &str) -> Result<&str, String> {
        self.one
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| format!("missing required option `{name}`"))
    }

    fn reject_unknown(&self, allowed: &[&str]) -> Result<(), String> {
        if let Some(unknown) = self
            .one
            .keys()
            .chain(self.many.keys())
            .find(|key| !allowed.contains(&key.as_str()))
        {
            Err(format!("unknown option `{unknown}`"))
        } else {
            Ok(())
        }
    }
}

fn usage() -> &'static str {
    "usage:\n  cigar-conformance run --profile <profile> (--executable <path>|--sdk-adapter <path>|--endpoint <url>) --implementation <name> [--build-digest sha256:<hex>] [--vectors <dir>] [--output <file>] [--isolation strict|portable]\n  cigar-conformance verify <result.json> [--vectors <dir>]\n  cigar-conformance traceability [--root <dir>] [--manifest <file>] [--output <file>]"
}
