// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

// Testing utilities
import { CommonTest } from "test/setup/CommonTest.sol";
import { Predeploys } from "src/libraries/Predeploys.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

import { GasPriceOracle } from "src/L2/GasPriceOracle.sol";

contract OtherTokenWETH {
    function name() public pure returns (string memory) {
        return "Wrapped Ether";
    }
}

contract OtherTokenNot {
    function name() public pure returns (string memory) {
        return "Not Wrapped Ether";
    }
}

contract MockOracle {
    address otherToken;
    bool goodReserves;

    constructor(address _otherToken, bool _goodReserves) {
        otherToken = _otherToken;
        goodReserves = _goodReserves;
    }

    function getReserves() public view returns (uint256, uint256, uint256) {
        // Let's say this is 2mm WTEA for 1 WETH
        // WTEA is token0 (at Predeploys.WETH)
        if (goodReserves) return (0, 1e18, 0);
        else return (0, 1e17, 0);
    }

    function factory() public view returns (address) {
        return address(this);
    }

    // TODO: is used to be called 'paused' is it test or oracle error?
    function isPaused() public view returns (bool) {
        return false;
    }

    function tokens() public view returns (address, address) {
        return (Predeploys.WETH, otherToken);
    }

    function quote(address token, uint256 amount, uint256) external pure returns (uint256) {
        if (token == Predeploys.WETH) {
            return amount / 2_000_000;
        } else {
            return amount * 2_000_000;
        }
    }
}

/// @dev Like MockOracle, but quotes a non-gwei-aligned rate so the old 1-gwei
///      sample would floor it while a full-1e18 sample preserves it (TEAO1-189).
contract PreciseMockOracle {
    address otherToken;

    constructor(address _otherToken) {
        otherToken = _otherToken;
    }

    function getReserves() public pure returns (uint256, uint256, uint256) {
        return (0, 1e18, 0);
    }

    function factory() public view returns (address) {
        return address(this);
    }

    function isPaused() public pure returns (bool) {
        return false;
    }

    function tokens() public view returns (address, address) {
        return (Predeploys.WETH, otherToken);
    }

    // 2_999_000_000 TEA-wei per 1e18 WETH. quote(1 gwei) floors to 2, which the
    // old code scaled back to 2_000_000_000; quote(1e18) yields the exact value.
    function quote(address, uint256 amount, uint256) external pure returns (uint256) {
        return amount * 2_999_000_000 / 1e18;
    }
}

contract TeaWAPOracle_Test is CommonTest {
    MockOracle public oracle;
    address myWeth;

    function setUp() public override {
        super.setUp();

        // Start at a reasonable timestamp.
        vm.warp(1737668792);

        myWeth = address(new OtherTokenWETH());
        oracle = new MockOracle(myWeth, true);
    }

    function testTeaWAP_UpdatePrice() public {
        vm.prank(address(l1Block));
        gasPriceOracle.updateGasTokenPriceRatio();

        (uint96 ts, uint160 price) = gasPriceOracle.getLatestPrice();
        assertEq(ts, block.timestamp);
        assertEq(price, 1_500_000e18);

        // This emulates what will happen in op-geth.
        bytes32 priceData = vm.load(address(gasPriceOracle), gasPriceOracle.CUSTOM_GAS_TOKEN_PRICE_SLOT());
        uint96 ts2 = uint96(uint256(priceData) >> 160);
        uint160 price2 = uint160(uint256(priceData));

        assertEq(ts2, block.timestamp);
        assertEq(price2, 1_500_000e18);
    }

    function testTeaWAP_SetUpOracle() public {
        vm.prank(Ownable(Predeploys.PROXY_ADMIN).owner());
        gasPriceOracle.setOracleConfig(10, 1e18, address(oracle));

        (address oracle_, uint16 twapObservations, uint80 minWethBalance, bool wethT0, address weth_) = gasPriceOracle.getOracleConfig();
        assertEq(oracle_, address(oracle));
        assertEq(twapObservations, 10);
        assertEq(minWethBalance, 1e18);
        assertFalse(wethT0);
        assertEq(weth_, myWeth);
    }

    function testTeaWAP_GetPriceFromOracle() public {
        vm.prank(Ownable(Predeploys.PROXY_ADMIN).owner());
        gasPriceOracle.setOracleConfig(10, 1e18, address(oracle));

        vm.prank(address(l1Block));
        gasPriceOracle.updateGasTokenPriceRatio();

        (uint96 ts, uint160 price) = gasPriceOracle.getLatestPrice();
        assertEq(ts, block.timestamp);
        assertEq(price, oracle.quote(myWeth, 1e18, 10));
    }

    function testTeaWAP_FallbackIfBadReserves() public {
        MockOracle badResevesOracle = new MockOracle(myWeth, false);
        vm.prank(Ownable(Predeploys.PROXY_ADMIN).owner());
        gasPriceOracle.setOracleConfig(10, 1e18, address(badResevesOracle));

        vm.prank(address(l1Block));
        gasPriceOracle.updateGasTokenPriceRatio();

        (uint96 ts, uint160 price) = gasPriceOracle.getLatestPrice();
        assertEq(ts, block.timestamp);
        assertEq(price, 1_500_000e18);
    }

    function testTeaWAP_StalePriceRevertToFallback() public {
        vm.prank(Ownable(Predeploys.PROXY_ADMIN).owner());
        gasPriceOracle.setOracleConfig(10, 1e18, address(oracle));

        vm.prank(address(l1Block));
        gasPriceOracle.updateGasTokenPriceRatio();

        (uint96 ts, uint160 price) = gasPriceOracle.getLatestPrice();
        assertEq(ts, block.timestamp);
        assertEq(price, 2_000_000e18);

        // now let's break the oracle
        vm.etch(address(oracle), abi.encode(""));

        // after 5 minutes, should still skip
        vm.warp(block.timestamp + 5 minutes);

        vm.prank(address(l1Block));
        gasPriceOracle.updateGasTokenPriceRatio();

        (uint96 newTs, uint160 newPrice) = gasPriceOracle.getLatestPrice();
        assertEq(ts, newTs);
        assertEq(price, newPrice);

        // but anything past 5 mins, we go to fallback
        vm.warp(block.timestamp + 1);

        vm.prank(address(l1Block));
        gasPriceOracle.updateGasTokenPriceRatio();

        (uint96 finalTs, uint160 finalPrice) = gasPriceOracle.getLatestPrice();
        assertEq(finalTs, block.timestamp);
        assertEq(finalPrice, 1_500_000e18);
    }

    /// TEAO1-189: sampling a full 1e18 of WETH must not quantize the price down
    /// to gwei precision. With a 2_999_000_000 rate, the old 1-gwei sample floored
    /// to 2_000_000_000; the full-WAD sample must preserve 2_999_000_000.
    function testTeaWAP_FullWadSampleNoQuantization() public {
        PreciseMockOracle p = new PreciseMockOracle(myWeth);
        vm.prank(Ownable(Predeploys.PROXY_ADMIN).owner());
        gasPriceOracle.setOracleConfig(10, 1e18, address(p));

        vm.prank(address(l1Block));
        gasPriceOracle.updateGasTokenPriceRatio();

        (, uint160 price) = gasPriceOracle.getLatestPrice();
        assertEq(price, 2_999_000_000, "full-1e18 sample must not floor to gwei precision");
    }

    /// TEAO1-185: convertETHToTea must read the cached price (5-minute grace),
    /// matching what execution settles against — not the live oracle, which flips
    /// to the fallback the instant it is unavailable.
    function testTeaWAP_ConvertUsesCachedNotLive() public {
        vm.prank(Ownable(Predeploys.PROXY_ADMIN).owner());
        gasPriceOracle.setOracleConfig(10, 1e18, address(oracle));

        vm.prank(address(l1Block));
        gasPriceOracle.updateGasTokenPriceRatio();

        (, uint160 cached) = gasPriceOracle.getLatestPrice();
        assertEq(cached, 2_000_000e18);

        // Break the live oracle. teaPerETH() would now return the fallback
        // (1_500_000e18), but the cached price is still valid within the grace
        // window and is what settlement uses.
        vm.etch(address(oracle), abi.encode(""));

        assertEq(
            GasPriceOracle(address(gasPriceOracle)).convertETHToTea(1e18),
            2_000_000e18,
            "convertETHToTea must use the cached price, not the live fallback"
        );
    }

    function testTeaWAP_NonWETHOracleFails() public {
        address notWeth = address(new OtherTokenNot());
        MockOracle nonWethOracle = new MockOracle(notWeth, true);

        vm.prank(Ownable(Predeploys.PROXY_ADMIN).owner());
        vm.expectRevert();
        gasPriceOracle.setOracleConfig(10, 1e18, address(nonWethOracle));
    }

    /// @dev SECURITY REGRESSION GUARD — only the owner may write the fallback
    ///      price. The fallback feeds L1-fee scaling whenever the live oracle is
    ///      unavailable, so an attacker-writable fallback would be a fee-
    ///      manipulation hole. A non-owner caller MUST revert and the stored
    ///      fallback MUST be unchanged.
    function testTeaWAP_setFallbackPrice_nonOwner_reverts() public {
        // getFallbackPrice is not on IGasPriceOracle; read via the concrete type.
        GasPriceOracle gpo = GasPriceOracle(address(gasPriceOracle));
        uint160 priceBefore = gpo.getFallbackPrice();

        vm.prank(makeAddr("attacker"));
        vm.expectRevert("TeaWAPOracle: admin only");
        gasPriceOracle.setFallbackPrice(123_456);

        assertEq(gpo.getFallbackPrice(), priceBefore, "fallback must be unchanged by a non-owner");
    }

    /// @dev SECURITY REGRESSION GUARD — only the owner may write the oracle
    ///      address / config slot. Pointing the oracle at an attacker-controlled
    ///      pool would let an attacker set the TEA/ETH price, so this must be
    ///      owner-gated. A non-owner caller MUST revert and the oracle address
    ///      MUST be unchanged.
    function testTeaWAP_setOracleConfig_nonOwner_reverts() public {
        (address oracleBefore,,,,) = gasPriceOracle.getOracleConfig();

        vm.prank(makeAddr("attacker"));
        vm.expectRevert("TeaWAPOracle: admin only");
        gasPriceOracle.setOracleConfig(10, 1e18, address(oracle));

        (address oracleAfter,,,,) = gasPriceOracle.getOracleConfig();
        assertEq(oracleAfter, oracleBefore, "oracle address must be unchanged by a non-owner");
    }
}
