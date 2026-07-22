//! `trustbeat` — anchor files to qualified eIDAS timestamps, verify them offline.

mod client;
mod config;
mod hashing;
mod merkle;
mod proof;
mod rfc3161;
mod ui;
mod verify;

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};

use crate::proof::Proof;
use crate::verify::{CheckStatus, Outcome};

#[derive(Parser)]
#[command(
    name = "trustbeat",
    version,
    about = "Anchor files to qualified eIDAS timestamps and verify the proofs offline.",
    long_about = None,
    after_help = "Docs: https://trustbeat.eu/docs   \
                  `trustbeat verify` works offline and needs no API key."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Hash a file (or take a hash) and submit it for qualified timestamping.
    Anchor(AnchorArgs),
    /// Verify a proof bundle. Fully offline — no API key, no network.
    Verify(VerifyArgs),
    /// Fetch the proof for a tracking id.
    Proof(ProofArgs),
    /// Print the SHA-256 of a file without sending anything anywhere.
    Hash(HashArgs),
}

#[derive(Args)]
struct AuthArgs {
    /// API key (default: $TRUSTBEAT_API_KEY, then ~/.config/trustbeat/credentials)
    #[arg(long, global = true, env = "TRUSTBEAT_API_KEY", hide_env_values = true)]
    api_key: Option<String>,
    /// API base URL
    #[arg(long, global = true)]
    api_url: Option<String>,
}

#[derive(Args)]
struct AnchorArgs {
    /// File to hash and anchor. The file itself is never uploaded.
    #[arg(value_name = "FILE", required_unless_present = "hash")]
    file: Option<PathBuf>,
    /// Anchor a SHA-256 digest directly instead of hashing a file.
    #[arg(long, conflicts_with = "file")]
    hash: Option<String>,
    /// Wait for the inclusion proof (batches anchor every ~10 minutes).
    #[arg(long)]
    wait: bool,
    /// Where to write the proof once it arrives. Default: <FILE>.proof.json
    #[arg(long, short = 'o', value_name = "PATH")]
    out: Option<PathBuf>,
    /// Your own reference, echoed back in the proof.
    #[arg(long)]
    client_ref: Option<String>,
    /// Human-readable description stored with the anchor.
    #[arg(long)]
    description: Option<String>,
    /// Seconds to wait with --wait.
    #[arg(long, default_value_t = 720)]
    timeout: u64,
    /// Machine-readable output.
    #[arg(long)]
    json: bool,
    #[command(flatten)]
    auth: AuthArgs,
}

#[derive(Args)]
struct VerifyArgs {
    /// Proof bundle written by `trustbeat anchor` (use - for stdin).
    #[arg(value_name = "PROOF")]
    proof: String,
    /// The original file, to prove the proof is about *this* document.
    #[arg(value_name = "FILE")]
    file: Option<PathBuf>,
    /// Machine-readable output.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct ProofArgs {
    /// Tracking id returned by `trustbeat anchor`.
    #[arg(value_name = "TRACKING_ID")]
    tracking_id: String,
    /// Write the proof here instead of stdout.
    #[arg(long, short = 'o', value_name = "PATH")]
    out: Option<PathBuf>,
    /// Wait until the proof is available.
    #[arg(long)]
    wait: bool,
    /// Seconds to wait with --wait.
    #[arg(long, default_value_t = 720)]
    timeout: u64,
    /// Machine-readable output.
    #[arg(long)]
    json: bool,
    #[command(flatten)]
    auth: AuthArgs,
}

#[derive(Args)]
struct HashArgs {
    /// File to hash.
    #[arg(value_name = "FILE")]
    file: PathBuf,
    /// Machine-readable output.
    #[arg(long)]
    json: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Anchor(a) => cmd_anchor(a),
        Command::Verify(a) => cmd_verify(a),
        Command::Proof(a) => cmd_proof(a),
        Command::Hash(a) => cmd_hash(a),
    };
    match result {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("{} {}", ui::red("error:"), msg);
            ExitCode::from(2)
        }
    }
}

// ── anchor ───────────────────────────────────────────────────────────────────

fn cmd_anchor(args: AnchorArgs) -> Result<ExitCode, String> {
    let (hash, source) = match (&args.file, &args.hash) {
        (Some(path), _) => {
            let h = hashing::hash_file(path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            (h, Some(path.clone()))
        }
        (None, Some(raw)) => (hashing::normalize_sha256_hex(raw)?, None),
        (None, None) => return Err("provide a FILE or --hash".into()),
    };

    let key = config::resolve_api_key(args.auth.api_key.clone())?;
    let url = config::resolve_api_url(args.auth.api_url.clone());
    let client = client::Client::new(key, url);

    let description = args.description.clone().or_else(|| {
        source
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().to_string())
    });

    let job = client
        .anchor(&hash, args.client_ref.as_deref(), description.as_deref())
        .map_err(|e| e.to_string())?;

    if !args.wait {
        if args.json {
            println!(
                "{}",
                serde_json::json!({ "id": job.id, "hash": hash, "status": "pending" })
            );
        } else {
            println!("{} sha256   {}", ui::tick(), hash);
            println!("{} submitted {}", ui::tick(), ui::dim(&job.id));
            println!();
            println!("The next batch anchors within ~10 minutes. Then:");
            println!("  trustbeat proof {}", job.id);
        }
        return Ok(ExitCode::SUCCESS);
    }

    if !args.json {
        println!("{} sha256   {}", ui::tick(), hash);
        println!("{} submitted {}", ui::tick(), ui::dim(&job.id));
        print!("{}", ui::dim("  waiting for the next anchor cycle… "));
        flush();
    }

    let proof = client
        .wait_for_proof(
            &job.id,
            Duration::from_secs(args.timeout),
            Duration::from_secs(15),
            |elapsed| {
                if !args.json {
                    print!(
                        "\r{}",
                        ui::dim(&format!(
                            "  waiting for the next anchor cycle… {}s ",
                            elapsed.as_secs()
                        ))
                    );
                    flush();
                }
            },
        )
        .map_err(|e| e.to_string())?;

    if !args.json {
        println!(
            "\r{}                                          ",
            ui::tick().to_string() + " anchored"
        );
    }

    let out_path = args.out.clone().or_else(|| {
        source.as_ref().map(|p| {
            let mut s = p.clone().into_os_string();
            s.push(".proof.json");
            PathBuf::from(s)
        })
    });
    write_proof(&proof, out_path.as_deref(), args.json)?;

    if !args.json {
        report_anchor(&proof, out_path.as_deref());
    }
    Ok(ExitCode::SUCCESS)
}

fn report_anchor(proof: &Proof, out: Option<&std::path::Path>) {
    if let Ok(token) = verify::base64_decode(&proof.token) {
        if let Ok(info) = rfc3161::inspect(&token) {
            println!(
                "  {} {}",
                ui::dim("time    "),
                ui::format_unix_utc(info.gen_time_unix)
            );
            println!(
                "  {} {}",
                ui::dim("tsa     "),
                verify::short_subject(&info.signer_subject)
            );
        }
    }
    if let Some(p) = out {
        println!("  {} {}", ui::dim("proof   "), p.display());
        println!();
        println!("Verify it anywhere, offline:");
        println!("  trustbeat verify {}", p.display());
    }
}

// ── verify ───────────────────────────────────────────────────────────────────

fn cmd_verify(args: VerifyArgs) -> Result<ExitCode, String> {
    let raw = if args.proof == "-" {
        use std::io::Read;
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| format!("cannot read stdin: {e}"))?;
        s
    } else {
        std::fs::read_to_string(&args.proof)
            .map_err(|e| format!("cannot read {}: {e}", args.proof))?
    };

    let proof: Proof = serde_json::from_str(&raw)
        .map_err(|e| format!("{} is not a valid proof bundle: {e}", args.proof))?;

    let document_hash = match &args.file {
        Some(path) => Some(
            hashing::hash_file(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?,
        ),
        None => None,
    };

    let outcome = verify::verify_proof(&proof, document_hash.as_deref());

    if args.json {
        println!("{}", verify_json(&proof, &outcome));
    } else {
        print_outcome(&proof, &outcome);
    }

    Ok(if outcome.is_valid() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn verify_json(proof: &Proof, outcome: &Outcome) -> String {
    let checks: Vec<serde_json::Value> = outcome
        .checks
        .iter()
        .map(|c| {
            serde_json::json!({
                "name": c.name,
                "status": match c.status {
                    CheckStatus::Pass => "pass",
                    CheckStatus::Fail => "fail",
                    CheckStatus::Skipped => "skipped",
                },
                "detail": c.detail,
            })
        })
        .collect();

    let mut out = serde_json::json!({
        "valid": outcome.is_valid(),
        "hash": proof.hash,
        "merkle_root": proof.merkle_root,
        "checks": checks,
    });
    if let Some(t) = &outcome.token {
        out["timestamp"] = serde_json::json!({
            "time": ui::format_unix_utc(t.gen_time_unix),
            "unix": t.gen_time_unix,
            "serial": t.serial_number,
            "signer": t.signer_subject,
            "imprint_algorithm": rfc3161::digest_name(&t.imprint_algorithm),
        });
    }
    serde_json::to_string_pretty(&out).unwrap_or_else(|_| "{}".into())
}

fn print_outcome(proof: &Proof, outcome: &Outcome) {
    for check in &outcome.checks {
        let mark = match check.status {
            CheckStatus::Pass => ui::tick(),
            CheckStatus::Fail => ui::cross(),
            CheckStatus::Skipped => ui::skip(),
        };
        println!("{mark} {:<10} {}", check.name, ui::dim(&check.detail));
    }
    println!();
    if let Some(t) = &outcome.token {
        println!(
            "  {} {}",
            ui::dim("anchored"),
            ui::format_unix_utc(t.gen_time_unix)
        );
        println!(
            "  {} {}",
            ui::dim("by      "),
            verify::short_subject(&t.signer_subject)
        );
        if !proof.provider.is_empty() {
            println!("  {} {}", ui::dim("provider"), proof.provider);
        }
        println!();
    }
    if outcome.is_valid() {
        println!("{}", ui::green(&ui::bold("PROOF VALID")));
    } else {
        println!("{}", ui::red(&ui::bold("PROOF INVALID")));
    }
}

// ── proof ────────────────────────────────────────────────────────────────────

fn cmd_proof(args: ProofArgs) -> Result<ExitCode, String> {
    let key = config::resolve_api_key(args.auth.api_key.clone())?;
    let url = config::resolve_api_url(args.auth.api_url.clone());
    let client = client::Client::new(key, url);

    let proof = if args.wait {
        client
            .wait_for_proof(
                &args.tracking_id,
                Duration::from_secs(args.timeout),
                Duration::from_secs(15),
                |_| {},
            )
            .map_err(|e| e.to_string())?
    } else {
        match client
            .get_proof(&args.tracking_id)
            .map_err(|e| e.to_string())?
        {
            Some(p) => p,
            None => {
                if args.json {
                    println!(
                        "{}",
                        serde_json::json!({ "id": args.tracking_id, "status": "pending" })
                    );
                } else {
                    println!(
                        "{} not anchored yet — the next batch runs within ~10 minutes",
                        ui::yellow("pending:")
                    );
                }
                return Ok(ExitCode::from(3));
            }
        }
    };

    write_proof(&proof, args.out.as_deref(), args.json)?;
    if !args.json && args.out.is_some() {
        report_anchor(&proof, args.out.as_deref());
    }
    Ok(ExitCode::SUCCESS)
}

// ── hash ─────────────────────────────────────────────────────────────────────

fn cmd_hash(args: HashArgs) -> Result<ExitCode, String> {
    let hash = hashing::hash_file(&args.file)
        .map_err(|e| format!("cannot read {}: {e}", args.file.display()))?;
    if args.json {
        println!(
            "{}",
            serde_json::json!({ "file": args.file.display().to_string(), "sha256": hash })
        );
    } else {
        println!("{hash}  {}", args.file.display());
    }
    Ok(ExitCode::SUCCESS)
}

// ── shared ───────────────────────────────────────────────────────────────────

fn write_proof(proof: &Proof, out: Option<&std::path::Path>, json: bool) -> Result<(), String> {
    let serialized =
        serde_json::to_string_pretty(proof).map_err(|e| format!("cannot serialize proof: {e}"))?;
    match out {
        Some(path) => {
            std::fs::write(path, serialized)
                .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({ "id": proof.id, "written": path.display().to_string() })
                );
            }
        }
        None => println!("{serialized}"),
    }
    Ok(())
}

fn flush() {
    use std::io::Write;
    let _ = std::io::stdout().flush();
}
