//! CLI argument parsing for the e2e test runner.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};

use crate::config::E2eConfig;

/// End-to-end test runner for a Mosaic instance.
#[derive(Parser)]
#[command(name = "mosaic-e2e")]
pub(crate) struct Cli {
    /// Path to the config file (same format as the mosaic binary config).
    #[arg(short = 'c', long = "config")]
    pub(crate) config_path: PathBuf,

    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Create a tableset between two mosaic nodes.
    Setup {
        /// Our role in the protocol.
        #[arg(value_enum)]
        role: Role,

        /// Hex-encoded peer ID of the other mosaic node.
        peer_id: String,

        /// Hex-encoded 32-byte setup inputs (defaults to all zeroes).
        #[arg(long)]
        setup_inputs: Option<String>,
    },

    /// Run setup for all (peer, role) pairs from the config.
    SetupAll {
        /// Hex-encoded 32-byte setup inputs (defaults to all zeroes).
        #[arg(long)]
        setup_inputs: Option<String>,
    },

    /// Initialise a deposit on a tableset.
    Deposit {
        /// Our role in the protocol.
        #[arg(value_enum)]
        role: Role,

        /// Hex-encoded peer ID of the other mosaic node.
        peer_id: String,

        /// Deposit index — determines the deposit ID and all derived values deterministically.
        deposit_idx: u32,

        /// Hex-encoded x-only adaptor public key (required for garbler role).
        #[arg(long)]
        adaptor_pk: Option<String>,

        /// Hex-encoded deposit input wire values (defaults to deterministic derivation from
        /// deposit index).
        #[arg(long)]
        deposit_inputs: Option<String>,
    },

    /// Exercise the withdrawal flow on a deposit.
    Withdrawal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum Role {
    Garbler,
    Evaluator,
}

/// Parsed CLI arguments.
pub(crate) struct Args {
    pub(crate) config: E2eConfig,
    pub(crate) command: Command,
}

impl Args {
    pub(crate) fn from_cli() -> Result<Self> {
        let cli = Cli::parse();
        let config = E2eConfig::from_file(&cli.config_path)?;
        Ok(Self {
            config,
            command: cli.command,
        })
    }
}
