// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// A Uniswap V3 pool and factory, only as far as the distributor uses them.
///
/// **The callback is the whole reason this exists rather than a stub.** A mock
/// that transferred the output and returned would let a distributor with no
/// `uniswapV3SwapCallback` at all pass every test, and the callback is the one
/// piece of that path carrying real risk. So this one pays out first, calls
/// back, and then *checks it was actually paid* -- which is what the real pool
/// does and is the only arrangement under which a broken callback fails here.
///
/// The pricing is constant product over the pool's own balances. That is not
/// what V3 does, and the difference does not matter for anything being checked:
/// every test here is about who may call what and what arrives, never about
/// concentrated liquidity maths. A mock that reimplemented tick crossing would
/// be a second implementation to get wrong.

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

interface IUniswapV3SwapCallback {
    function uniswapV3SwapCallback(int256 amount0Delta, int256 amount1Delta, bytes calldata data) external;
}

contract MockV3Pool {
    address public immutable token0;
    address public immutable token1;
    uint24 public immutable fee;

    /// Set by the harness to make the pool underpay, so `minOut` has something
    /// to catch. Without it the slippage bound is unreachable and the test
    /// asserting it fires would be asserting nothing.
    uint256 public shortfallBps;

    /// Set by the harness to make the pool ask for nothing back, which is the
    /// shape a malicious pool would use against a callback that paid whatever
    /// it was told.
    bool public askForNothing;

    error NotPaid();

    constructor(address a, address b, uint24 fee_) {
        (token0, token1) = a < b ? (a, b) : (b, a);
        fee = fee_;
    }

    function setShortfall(uint256 bps) external { shortfallBps = bps; }
    function setAskForNothing(bool v) external { askForNothing = v; }

    /// Split from `swap` only because the whole thing in one body is stack-too-
    /// deep under the same optimiser settings the real contract is built with,
    /// and building the mock differently from the thing it tests is how a test
    /// harness starts lying.
    function _out(bool zeroForOne, uint256 amountIn) private view returns (uint256 out) {
        uint256 rIn = IERC20(zeroForOne ? token0 : token1).balanceOf(address(this));
        uint256 rOut = IERC20(zeroForOne ? token1 : token0).balanceOf(address(this));
        out = (amountIn * 997 * rOut) / (rIn * 1000 + amountIn * 997);
        if (shortfallBps > 0) out = out - (out * shortfallBps) / 10000;
    }

    function swap(address recipient, bool zeroForOne, int256 amountSpecified, uint160, bytes calldata data)
        external
        returns (int256 amount0, int256 amount1)
    {
        require(amountSpecified > 0, "exact input only");
        uint256 owedBefore = IERC20(zeroForOne ? token0 : token1).balanceOf(address(this));

        // Output first, then ask for payment. This ordering is the point of the
        // mock: it is what makes a missing or broken callback fail here.
        IERC20(zeroForOne ? token1 : token0).transfer(recipient, _out(zeroForOne, uint256(amountSpecified)));

        int256 owe = askForNothing ? int256(0) : amountSpecified;
        (amount0, amount1) = zeroForOne ? (owe, int256(0)) : (int256(0), owe);
        IUniswapV3SwapCallback(msg.sender).uniswapV3SwapCallback(amount0, amount1, data);

        if (!askForNothing) {
            uint256 now_ = IERC20(zeroForOne ? token0 : token1).balanceOf(address(this));
            if (now_ < owedBefore + uint256(amountSpecified)) revert NotPaid();
        }
    }
}

contract MockV3Factory {
    mapping(bytes32 => address) private _pools;

    function record(address pool, address a, address b, uint24 fee) external {
        (address t0, address t1) = a < b ? (a, b) : (b, a);
        _pools[keccak256(abi.encode(t0, t1, fee))] = pool;
    }

    function getPool(address a, address b, uint24 fee) external view returns (address) {
        (address t0, address t1) = a < b ? (a, b) : (b, a);
        return _pools[keccak256(abi.encode(t0, t1, fee))];
    }
}
