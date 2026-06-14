#![allow(missing_docs)]
//! TEAO1-211 regression test (fix for finding 111da8ae).
//!
//! The Tea receipt fix rehydrates `l1_cost_multiplier` from the parent block's
//! `GasPriceOracle` state. On a pruned node `history_by_block_number(parent)`
//! returns `StateAtBlockPruned`, which previously failed the whole receipt RPC
//! with `OpEthApiError::L1BlockFeeError`. The fix degrades gracefully: the receipt
//! is still returned, with `l1Fee` omitted (`None`) rather than a wrong value or an
//! error. This test drives the real `OpReceiptConverter` with a provider whose
//! `history_by_block_number` is pruned and asserts that fixed behavior, plus the
//! off-Tea control (state-free, raw fee preserved).

use alloy_consensus::{transaction::TransactionMeta, Block, BlockBody, Eip658Value, Header, Receipt};
use alloy_eips::{BlockHashOrNumber, BlockNumberOrTag, Decodable2718};
use alloy_primitives::{hex, Address, B256, TxHash};
use op_alloy_consensus::OpReceipt;
use reth_chainspec::{Chain, ChainInfo, ChainSpecProvider};
use reth_db_models::StoredBlockBodyIndices;
use reth_optimism_chainspec::OpChainSpecBuilder;
use reth_optimism_primitives::{OpPrimitives, OpTransactionSigned};
use reth_optimism_rpc::eth::receipt::OpReceiptConverter;
use reth_primitives_traits::{Recovered, RecoveredBlock, SealedBlock, SealedHeader};
use reth_rpc_eth_api::transaction::{ConvertReceiptInput, ReceiptConverter};
use reth_storage_api::{
    noop::NoopProvider, BlockBodyIndicesProvider, BlockHashReader, BlockIdReader, BlockNumReader,
    BlockReader, BlockSource, HeaderProvider, ReceiptProvider, StateProviderBox,
    StateProviderFactory, TransactionVariant, TransactionsProvider,
};
use reth_storage_errors::provider::{ProviderError, ProviderResult};
use std::{
    ops::{RangeBounds, RangeInclusive},
    sync::Arc,
};

const TX_SET_L1_BLOCK: [u8; 251] = hex!(
    "7ef8f8a0683079df94aa5b9cf86687d739a60a9b4f0835e520ec4d664e2e415dca17a6df94deaddeaddeaddeaddeaddeaddeaddeaddead00019442000000000000000000000000000000000000158080830f424080b8a4440a5e200000146b000f79c500000000000000040000000066d052e700000000013ad8a3000000000000000000000000000000000000000000000000000000003ef1278700000000000000000000000000000000000000000000000000000000000000012fdf87b89884a61e74b322bbcf60386f543bfae7827725efaaf0ab1de2294a590000000000000000000000006887246668a3b87f54deb3b94ba47a6f63f32985"
);
const TX_1: [u8; 1176] = hex!(
    "02f904940a8303fba78401d6d2798401db2b6d830493e0943e6f4f7866654c18f536170780344aa8772950b680b904246a761202000000000000000000000000087000a300de7200382b55d40045000000e5d60e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003a0000000000000000000000000000000000000000000000000000000000000022482ad56cb0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000120000000000000000000000000dc6ff44d5d932cbd77b52e5612ba0529dc6226f1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000044095ea7b300000000000000000000000021c4928109acb0659a88ae5329b5374a3024694c0000000000000000000000000000000000000000000000049b9ca9a6943400000000000000000000000000000000000000000000000000000000000000000000000000000000000021c4928109acb0659a88ae5329b5374a3024694c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000024b6b55f250000000000000000000000000000000000000000000000049b9ca9a694340000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000415ec214a3950bea839a7e6fbb0ba1540ac2076acd50820e2d5ef83d0902cdffb24a47aff7de5190290769c4f0a9c6fabf63012986a0d590b1b571547a8c7050ea1b00000000000000000000000000000000000000000000000000000000000000c080a06db770e6e25a617fe9652f0958bd9bd6e49281a53036906386ed39ec48eadf63a07f47cf51a4a40b4494cf26efc686709a9b03939e20ee27e59682f5faa536667e"
);
const TS: u64 = 1724928889;
const BLOCK_NUMBER: u64 = 124665056;

/// Wraps any provider but reports `history_by_block_number` as pruned — the exact
/// shape of a node that keeps block bodies/receipts but has pruned account/storage
/// history.
#[derive(Debug, Clone)]
struct PrunedHistory<T>(T);

impl<T: BlockHashReader> BlockHashReader for PrunedHistory<T> {
    fn block_hash(&self, number: u64) -> ProviderResult<Option<B256>> { self.0.block_hash(number) }
    fn canonical_hashes_range(&self, start: u64, end: u64) -> ProviderResult<Vec<B256>> { self.0.canonical_hashes_range(start, end) }
}
impl<T: BlockNumReader> BlockNumReader for PrunedHistory<T> {
    fn chain_info(&self) -> ProviderResult<ChainInfo> { self.0.chain_info() }
    fn best_block_number(&self) -> ProviderResult<u64> { self.0.best_block_number() }
    fn last_block_number(&self) -> ProviderResult<u64> { self.0.last_block_number() }
    fn block_number(&self, hash: B256) -> ProviderResult<Option<u64>> { self.0.block_number(hash) }
}
impl<T: BlockIdReader> BlockIdReader for PrunedHistory<T> {
    fn pending_block_num_hash(&self) -> ProviderResult<Option<alloy_eips::BlockNumHash>> { self.0.pending_block_num_hash() }
    fn safe_block_num_hash(&self) -> ProviderResult<Option<alloy_eips::BlockNumHash>> { self.0.safe_block_num_hash() }
    fn finalized_block_num_hash(&self) -> ProviderResult<Option<alloy_eips::BlockNumHash>> { self.0.finalized_block_num_hash() }
}
impl<T: HeaderProvider> HeaderProvider for PrunedHistory<T> {
    type Header = T::Header;
    fn header(&self, block_hash: B256) -> ProviderResult<Option<Self::Header>> { self.0.header(block_hash) }
    fn header_by_number(&self, num: u64) -> ProviderResult<Option<Self::Header>> { self.0.header_by_number(num) }
    fn headers_range(&self, range: impl RangeBounds<u64>) -> ProviderResult<Vec<Self::Header>> { self.0.headers_range(range) }
    fn sealed_header(&self, number: u64) -> ProviderResult<Option<SealedHeader<Self::Header>>> { self.0.sealed_header(number) }
    fn sealed_headers_while(&self, range: impl RangeBounds<u64>, predicate: impl FnMut(&SealedHeader<Self::Header>) -> bool) -> ProviderResult<Vec<SealedHeader<Self::Header>>> { self.0.sealed_headers_while(range, predicate) }
}
impl<T: BlockBodyIndicesProvider> BlockBodyIndicesProvider for PrunedHistory<T> {
    fn block_body_indices(&self, num: u64) -> ProviderResult<Option<StoredBlockBodyIndices>> { self.0.block_body_indices(num) }
    fn block_body_indices_range(&self, range: RangeInclusive<u64>) -> ProviderResult<Vec<StoredBlockBodyIndices>> { self.0.block_body_indices_range(range) }
}
impl<T: TransactionsProvider> TransactionsProvider for PrunedHistory<T> {
    type Transaction = T::Transaction;
    fn transaction_id(&self, tx_hash: TxHash) -> ProviderResult<Option<u64>> { self.0.transaction_id(tx_hash) }
    fn transaction_by_id(&self, id: u64) -> ProviderResult<Option<Self::Transaction>> { self.0.transaction_by_id(id) }
    fn transaction_by_id_unhashed(&self, id: u64) -> ProviderResult<Option<Self::Transaction>> { self.0.transaction_by_id_unhashed(id) }
    fn transaction_by_hash(&self, hash: TxHash) -> ProviderResult<Option<Self::Transaction>> { self.0.transaction_by_hash(hash) }
    fn transaction_by_hash_with_meta(&self, hash: TxHash) -> ProviderResult<Option<(Self::Transaction, TransactionMeta)>> { self.0.transaction_by_hash_with_meta(hash) }
    fn transactions_by_block(&self, block: BlockHashOrNumber) -> ProviderResult<Option<Vec<Self::Transaction>>> { self.0.transactions_by_block(block) }
    fn transactions_by_block_range(&self, range: impl RangeBounds<u64>) -> ProviderResult<Vec<Vec<Self::Transaction>>> { self.0.transactions_by_block_range(range) }
    fn transactions_by_tx_range(&self, range: impl RangeBounds<u64>) -> ProviderResult<Vec<Self::Transaction>> { self.0.transactions_by_tx_range(range) }
    fn senders_by_tx_range(&self, range: impl RangeBounds<u64>) -> ProviderResult<Vec<Address>> { self.0.senders_by_tx_range(range) }
    fn transaction_sender(&self, id: u64) -> ProviderResult<Option<Address>> { self.0.transaction_sender(id) }
}
impl<T: ReceiptProvider> ReceiptProvider for PrunedHistory<T> {
    type Receipt = T::Receipt;
    fn receipt(&self, id: u64) -> ProviderResult<Option<Self::Receipt>> { self.0.receipt(id) }
    fn receipt_by_hash(&self, hash: TxHash) -> ProviderResult<Option<Self::Receipt>> { self.0.receipt_by_hash(hash) }
    fn receipts_by_block(&self, block: BlockHashOrNumber) -> ProviderResult<Option<Vec<Self::Receipt>>> { self.0.receipts_by_block(block) }
    fn receipts_by_tx_range(&self, range: impl RangeBounds<u64>) -> ProviderResult<Vec<Self::Receipt>> { self.0.receipts_by_tx_range(range) }
    fn receipts_by_block_range(&self, range: RangeInclusive<u64>) -> ProviderResult<Vec<Vec<Self::Receipt>>> { self.0.receipts_by_block_range(range) }
}
impl<T: BlockReader> BlockReader for PrunedHistory<T> {
    type Block = T::Block;
    fn find_block_by_hash(&self, hash: B256, source: BlockSource) -> ProviderResult<Option<Self::Block>> { self.0.find_block_by_hash(hash, source) }
    fn block(&self, id: BlockHashOrNumber) -> ProviderResult<Option<Self::Block>> { self.0.block(id) }
    fn pending_block(&self) -> ProviderResult<Option<RecoveredBlock<Self::Block>>> { self.0.pending_block() }
    fn pending_block_and_receipts(&self) -> ProviderResult<Option<(RecoveredBlock<Self::Block>, Vec<Self::Receipt>)>> { self.0.pending_block_and_receipts() }
    fn recovered_block(&self, id: BlockHashOrNumber, kind: TransactionVariant) -> ProviderResult<Option<RecoveredBlock<Self::Block>>> { self.0.recovered_block(id, kind) }
    fn sealed_block_with_senders(&self, id: BlockHashOrNumber, kind: TransactionVariant) -> ProviderResult<Option<RecoveredBlock<Self::Block>>> { self.0.sealed_block_with_senders(id, kind) }
    fn block_range(&self, range: RangeInclusive<u64>) -> ProviderResult<Vec<Self::Block>> { self.0.block_range(range) }
    fn block_with_senders_range(&self, range: RangeInclusive<u64>) -> ProviderResult<Vec<RecoveredBlock<Self::Block>>> { self.0.block_with_senders_range(range) }
    fn recovered_block_range(&self, range: RangeInclusive<u64>) -> ProviderResult<Vec<RecoveredBlock<Self::Block>>> { self.0.recovered_block_range(range) }
    fn block_by_transaction_id(&self, id: u64) -> ProviderResult<Option<u64>> { self.0.block_by_transaction_id(id) }
}
impl<T: ChainSpecProvider> ChainSpecProvider for PrunedHistory<T> {
    type ChainSpec = T::ChainSpec;
    fn chain_spec(&self) -> Arc<Self::ChainSpec> { self.0.chain_spec() }
}
impl<T: StateProviderFactory> StateProviderFactory for PrunedHistory<T> {
    fn latest(&self) -> ProviderResult<StateProviderBox> { self.0.latest() }
    fn state_by_block_number_or_tag(&self, number_or_tag: BlockNumberOrTag) -> ProviderResult<StateProviderBox> { self.0.state_by_block_number_or_tag(number_or_tag) }
    fn history_by_block_number(&self, block: u64) -> ProviderResult<StateProviderBox> { Err(ProviderError::StateAtBlockPruned(block)) }
    fn history_by_block_hash(&self, block: B256) -> ProviderResult<StateProviderBox> { self.0.history_by_block_hash(block) }
    fn state_by_block_hash(&self, block: B256) -> ProviderResult<StateProviderBox> { self.0.state_by_block_hash(block) }
    fn pending(&self) -> ProviderResult<StateProviderBox> { self.0.pending() }
    fn pending_state_by_hash(&self, block_hash: B256) -> ProviderResult<Option<StateProviderBox>> { self.0.pending_state_by_hash(block_hash) }
    fn maybe_pending(&self) -> ProviderResult<Option<StateProviderBox>> { self.0.maybe_pending() }
}

fn make_block_and_inputs() -> (SealedBlock<Block<OpTransactionSigned>>, Vec<ConvertReceiptInput<'static, OpPrimitives>>) {
    let tx_1 = OpTransactionSigned::decode_2718(&mut TX_1.as_slice()).unwrap();
    let tx_1_static: &'static OpTransactionSigned = Box::leak(Box::new(tx_1.clone()));
    let block: Block<OpTransactionSigned> = Block {
        header: Header { number: BLOCK_NUMBER, ..Default::default() },
        body: BlockBody {
            transactions: vec![
                OpTransactionSigned::decode_2718(&mut TX_SET_L1_BLOCK.as_slice()).unwrap(),
                tx_1.clone(),
            ],
            ..Default::default()
        },
        ..Default::default()
    };
    let input = ConvertReceiptInput::<OpPrimitives> {
        tx: Recovered::new_unchecked(tx_1_static, Address::ZERO),
        receipt: OpReceipt::Eip1559(Receipt {
            status: Eip658Value::Eip658(true),
            cumulative_gas_used: 100,
            logs: vec![],
        }),
        gas_used: 100,
        next_log_index: 0,
        meta: TransactionMeta { block_number: BLOCK_NUMBER, timestamp: TS, ..Default::default() },
    };
    (SealedBlock::new_unhashed(block), vec![input])
}

/// TEAO1-211 (fixed): pruned parent state must NOT fail the receipt RPC. The
/// receipt is returned with `l1Fee` omitted (`None`) — never a wrong fee, never an
/// error.
#[test]
fn tea_receipt_pruned_parent_omits_l1fee_instead_of_failing() {
    let tea_spec = Arc::new(OpChainSpecBuilder::optimism_mainnet().chain(Chain::from_id(6122)).build());
    let provider = PrunedHistory(NoopProvider::<_, OpPrimitives>::new(tea_spec));
    let converter = OpReceiptConverter::new(provider);
    let (block, inputs) = make_block_and_inputs();

    // The previous fix errored here (`L1BlockFeeError`); the graceful-degradation
    // fix returns the receipt with l1Fee omitted.
    let receipts = converter
        .convert_receipts_with_block(inputs, &block)
        .expect("pruned parent state must NOT fail the receipt RPC (TEAO1-211)");
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts[0].l1_block_info.l1_fee, None,
        "l1Fee must be omitted (None) when the historical oracle ratio is unreadable — \
         not a raw/backup-rate wrong value, and not an error"
    );
}

/// Control: off-Tea conversion never touches parent state, so a pruned provider is
/// irrelevant and the raw OP `l1Fee` is reported unchanged (no regression).
#[test]
fn off_tea_receipt_conversion_does_not_require_parent_state() {
    let op_spec = Arc::new(OpChainSpecBuilder::optimism_mainnet().build());
    let provider = PrunedHistory(NoopProvider::<_, OpPrimitives>::new(op_spec));
    let converter = OpReceiptConverter::new(provider);
    let (block, inputs) = make_block_and_inputs();
    let receipts = converter.convert_receipts_with_block(inputs, &block).unwrap();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].l1_block_info.l1_fee, Some(24_681_034_813));
}
