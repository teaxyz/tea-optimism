//! Tea-reth: Custom OP Stack execution client for the Tea L2 chain.
//!
//! This binary wraps op-reth. Tea-specific EVM customizations (GPG precompile,
//! TEA/ETH L1 cost multiplier) are injected at the `alloy-op-evm` layer via
//! the `tea-precompiles` crate, so no custom executor builder is needed here.

use clap::Parser;
use reth_op::node::OpNode;
use reth_op::node::builder::Node;
use reth_optimism_cli::{Cli, chainspec::OpChainSpecParser};
use reth_op::node::args::RollupArgs;
use tracing::info;

fn main() {
    reth_cli_util::sigsegv_handler::install();

    if std::env::var_os("RUST_BACKTRACE").is_none() {
        unsafe {
            std::env::set_var("RUST_BACKTRACE", "1");
        }
    }

    if let Err(err) =
        Cli::<OpChainSpecParser, RollupArgs>::parse().run(async move |builder, rollup_args| {
            let node = OpNode::new(rollup_args);

            info!(target: "tea_reth", "Launching Tea node (precompiles injected via alloy-op-evm)");

            let handle = builder
                .with_types::<OpNode>()
                .with_components(node.components())
                .with_add_ons(node.add_ons())
                .launch_with_debug_capabilities()
                .await?;

            handle.node_exit_future.await
        })
    {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}
