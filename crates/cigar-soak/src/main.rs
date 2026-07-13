//! `cigar-soak` strict command-line entry point.

use cigar_soak::{
    LoadedPlan, PlanBindings, SoakError, SoakProfile, generate_plan, verify_result, write_new_plan,
};
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run(std::env::args_os().skip(1).collect()) {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(arguments: Vec<OsString>) -> Result<String, SoakError> {
    let command = arguments
        .first()
        .and_then(|value| value.to_str())
        .ok_or(SoakError::InvalidDocument)?;
    let command_arguments = arguments.get(1..).ok_or(SoakError::InvalidDocument)?;
    match command {
        "plan" => plan_command(command_arguments),
        "verify" => verify_command(command_arguments),
        "run" | "run-reviewed" => Err(SoakError::DriverUnavailable),
        _ => Err(SoakError::InvalidDocument),
    }
}

fn plan_command(arguments: &[OsString]) -> Result<String, SoakError> {
    let values = parse_pairs(arguments)?;
    let profile = required(&values, "--profile")
        .and_then(|value| SoakProfile::from_id(value).ok_or(SoakError::InvalidPlan))?;
    let output = absolute_path(required(&values, "--out")?)?;
    let source_revision = required(&values, "--source-revision")?.to_owned();
    let daemon_digest = required(&values, "--daemon-digest")?.to_owned();
    let profile_digest = required(&values, "--profile-digest")?.to_owned();
    let seed = required(&values, "--seed")?
        .parse::<u64>()
        .map_err(|_error| SoakError::InvalidPlan)?;
    if values.len() != 6 {
        return Err(SoakError::InvalidDocument);
    }
    let plan = generate_plan(
        profile,
        seed,
        PlanBindings::new(source_revision, daemon_digest, profile_digest),
    )?;
    let plan_id = plan.id().to_owned();
    write_new_plan(&output, &plan)?;
    Ok(format!("created soak plan {plan_id}"))
}

fn verify_command(arguments: &[OsString]) -> Result<String, SoakError> {
    let values = parse_pairs(arguments)?;
    let plan_path = absolute_path(required(&values, "--plan")?)?;
    let result_path = absolute_path(required(&values, "--result")?)?;
    if values.len() != 2 {
        return Err(SoakError::InvalidDocument);
    }
    let plan = LoadedPlan::load(&plan_path)?;
    let result = verify_result(&plan, &result_path)?;
    Ok(format!(
        "verified soak result {} status {}",
        result.result_id(),
        result.status()
    ))
}

fn parse_pairs(arguments: &[OsString]) -> Result<Vec<(String, String)>, SoakError> {
    if arguments.is_empty() || !arguments.len().is_multiple_of(2) {
        return Err(SoakError::InvalidDocument);
    }
    let mut pairs = Vec::with_capacity(arguments.len() / 2);
    for pair in arguments.chunks_exact(2) {
        let name = pair
            .first()
            .and_then(|value| value.to_str())
            .ok_or(SoakError::InvalidDocument)?;
        let value = pair
            .get(1)
            .and_then(|value| value.to_str())
            .ok_or(SoakError::InvalidDocument)?;
        if !name.starts_with("--")
            || value.is_empty()
            || pairs.iter().any(|(existing, _)| existing == name)
        {
            return Err(SoakError::InvalidDocument);
        }
        pairs.push((name.to_owned(), value.to_owned()));
    }
    Ok(pairs)
}

fn required<'a>(values: &'a [(String, String)], name: &str) -> Result<&'a str, SoakError> {
    values
        .iter()
        .find(|(candidate, _)| candidate == name)
        .map(|(_, value)| value.as_str())
        .ok_or(SoakError::InvalidDocument)
}

fn absolute_path(value: &str) -> Result<PathBuf, SoakError> {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(SoakError::Unavailable)
    }
}
