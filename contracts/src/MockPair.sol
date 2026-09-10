// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface IToken {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
}

/// A Uniswap V2 pair, enough of one to test a distributor against.
///
/// **This exists to test our contract, not Uniswap's.** The arithmetic is the
/// real constant product with the real 0.3% fee and the real `k` check, because
/// the distributor computes the output itself now -- so a mock that accepted
/// any `amountOut` would let an arithmetic error pass, which is precisely the
/// error worth catching when the router that used to do that sum is gone.
///
/// Token order matters and is modelled: a real pair sorts its two tokens by
/// address and `swap` takes outputs positionally. Getting that backwards asks
/// the pool to pay out the token being paid in, and this refuses it the way a
/// real pair does -- by failing the `k` check.
contract MockPair {
    address public immutable token0;
    address public immutable token1;

    uint112 private r0;
    uint112 private r1;

    error K();
    error Liquidity();
    error Output();

    constructor(address a, address b) {
        (token0, token1) = a < b ? (a, b) : (b, a);
    }

    function getReserves() external view returns (uint112, uint112, uint32) {
        return (r0, r1, uint32(block.timestamp));
    }

    function seed(uint256 a0, uint256 a1) external {
        IToken(token0).transferFrom(msg.sender, address(this), a0);
        IToken(token1).transferFrom(msg.sender, address(this), a1);
        _sync();
    }

    function _sync() private {
        r0 = uint112(IToken(token0).balanceOf(address(this)));
        r1 = uint112(IToken(token1).balanceOf(address(this)));
    }

    /// Uniswap V2's own `swap`, minus flash loans and fee-to.
    ///
    /// The `k` check is the real one and is the reason this is worth having: it
    /// is what a pair uses instead of trusting the caller's arithmetic, so a
    /// distributor that computed its output wrong is refused here exactly as it
    /// would be on chain.
    function swap(uint256 a0Out, uint256 a1Out, address to, bytes calldata) external {
        if (a0Out == 0 && a1Out == 0) revert Output();
        if (a0Out >= r0 || a1Out >= r1) revert Liquidity();

        if (a0Out > 0) IToken(token0).transfer(to, a0Out);
        if (a1Out > 0) IToken(token1).transfer(to, a1Out);
        uint256 b0 = IToken(token0).balanceOf(address(this));
        uint256 b1 = IToken(token1).balanceOf(address(this));

        // **Against the stored reserves, not a fresh balance read.** The input
        // has already arrived by the time `swap` is called -- that is how a V2
        // swap works -- so a balance taken at the top of this function already
        // includes it and the input computes as zero every time. Uniswap uses
        // `_reserve0` here for exactly this reason. Written the other way
        // first, and every swap reverted with `Output()`.
        uint256 in0 = b0 > r0 - a0Out ? b0 - (r0 - a0Out) : 0;
        uint256 in1 = b1 > r1 - a1Out ? b1 - (r1 - a1Out) : 0;
        if (in0 == 0 && in1 == 0) revert Output();

        // Balances after the 0.3% fee, against the reserves before. The
        // multiplication by 1000 is Uniswap's own way of keeping it integral.
        uint256 adj0 = b0 * 1000 - in0 * 3;
        uint256 adj1 = b1 * 1000 - in1 * 3;
        if (adj0 * adj1 < uint256(r0) * uint256(r1) * 1_000_000) revert K();
        _sync();
    }
}
