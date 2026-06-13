// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

// Libraries
import { Predeploys } from "src/libraries/Predeploys.sol";

// Interfaces
import { IL1Block } from "interfaces/L2/IL1Block.sol";

// Standard OP fee oracle (base) + TEA cached-price machinery
import { GasPriceOracleStandard } from "./GasPriceOracleStandard.sol";
import { TeaWAPOracle } from "./TeaWAPOracle.sol";

/// @custom:proxied true
/// @custom:predeploy 0x420000000000000000000000000000000000000F
/// @title GasPriceOracle
/// @notice The custom-gas-token (CGT) GasPriceOracle for Tea chains. It is the standard OP
///         [`GasPriceOracleStandard`] PLUS the TEA/ETH price machinery from [`TeaWAPOracle`]:
///         the L1 fee is denominated in the custom gas token by multiplying the standard fee by
///         the cached TEA/ETH ratio. Installed only on CGT deployments; non-CGT ("standard")
///         chains install [`GasPriceOracleStandard`] directly (TEAO1-165), so the cached-price
///         slot, `updateGasTokenPriceRatio`, and the multiplier never ride onto a chain whose
///         L1Block can't write the slot.
///
/// @dev Inheritance order is `GasPriceOracleStandard, TeaWAPOracle` so the fork-flag bools sit at
///      storage slot 0 in BOTH oracles (TeaWAPOracle's `owner` follows at slot 1). That shared
///      layout lets the deploy-time gate swap the two implementations at the same predeploy
///      address with identical fee-flag storage. `owner` defaults to `PROXY_ADMIN.owner()` and is
///      never written at genesis, so moving it off slot 0 is safe.
contract GasPriceOracle is GasPriceOracleStandard, TeaWAPOracle {
    /// @notice Semantic version.
    /// @custom:semver 1.6.0+CGT
    function version() external view override returns (string memory) {
        return "1.6.0+CGT";
    }

    /// @notice Event emitted if the oracle fails.
    /// @dev This can be used by an off chain watcher to notify the team to
    ///      investigate the oracle and ensure the fallback price is accurate.
    event OracleReturnedFallbackPrice();

    /// @notice Computes the L1 portion of the fee, denominated in the custom gas token by scaling
    ///         the standard OP fee by the cached TEA/ETH ratio (TEAO1-165/170/133/161).
    /// @param _data Unsigned fully RLP-encoded transaction to get the L1 fee for.
    /// @return L1 fee that should be paid for the tx
    function getL1Fee(bytes memory _data) external view override returns (uint256) {
        return _cachedPriceOrBackup() * _rawL1Fee(_data) / 1e18;
    }

    /// @notice TEA-denominated upper bound for the L1 fee for a given transaction size.
    /// @param _unsignedTxSize Unsigned fully RLP-encoded transaction size to get the L1 fee for.
    /// @return L1 estimated upper-bound fee that should be paid for the tx
    function getL1FeeUpperBound(uint256 _unsignedTxSize) external view override returns (uint256) {
        return _cachedPriceOrBackup() * _rawL1FeeUpperBound(_unsignedTxSize) / 1e18;
    }

    /// @notice The TEA/ETH multiplier the fee helpers apply, as a 1e18-scaled ratio. Uses the
    ///         cached price, falling back to the backup rate while the slot is unwritten (genesis
    ///         bootstrap) or during oracle downtime. As defense-in-depth, if this CGT oracle is
    ///         ever installed where the L1Block reports non-CGT, it returns the identity
    ///         multiplier (1e18) so the fee reduces to the standard OP fee (TEAO1-165).
    function _cachedPriceOrBackup() internal view returns (uint160) {
        if (!IL1Block(Predeploys.L1_BLOCK_ATTRIBUTES).isCustomGasToken()) {
            return uint160(1e18);
        }
        (, uint160 latestPrice) = getLatestPrice();
        if (latestPrice == 0) return getFallbackPrice();
        return latestPrice;
    }

    /// @notice Pulls the latest price from the oracle and updates the ratio storage slot.
    /// @dev This function MUST NOT revert, as it is called by the System TX when updating L1Block.sol.
    function updateGasTokenPriceRatio() external {
        require(msg.sender == Predeploys.L1_BLOCK_ATTRIBUTES, "GasPriceOracle: only L1_BLOCK_ATTRIBUTES can update");

        // The oracle calculates the current price of 1e18 ETH in TEA (18 decimals).
        (bool validPrice, uint160 currentPrice) = teaPerETH();

        // If the call didn't return the fallback price, it succeeded.
        if (validPrice) {
            _setLatestPrice(currentPrice);
        } else {
            // If the call returned the fallback price, it failed.
            emit OracleReturnedFallbackPrice();

            // If the last result is from within the past 5 minutes, keep it.
            // Otherwise, replace it with currentPrice (fallback)
            (uint96 lastUpdate, uint160 lastPrice) = getLatestPrice();
            if (currentPrice != lastPrice) {
                if (block.timestamp > lastUpdate + MAX_ORACLE_DOWNTIME) {
                    _setLatestPrice(currentPrice);
                }
            }
        }
    }
}
