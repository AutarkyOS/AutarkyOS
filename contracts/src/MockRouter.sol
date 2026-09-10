// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface IToken {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
}

/// A constant-product router, enough of one to test a distributor against.
///
/// **This exists to test our contract, not Uniswap's.** The AMM arithmetic
/// here is the real `x*y/k` with the real 0.3% fee, because the distributor's
/// behaviour depends on the output being *variable and unknown in advance* --
/// a mock returning a fixed rate would let a bug that ignores the return value
/// pass. What it deliberately does not model is anything about Uniswap that is
/// Uniswap's problem: pair creation, multi-hop paths, permit, or the plain
/// `swapExactTokensForTokens` this distributor cannot use anyway.
///
/// The buy tax is here because the real token has one, and because the
/// interesting property of the fee-on-transfer variant is precisely that the
/// amount arriving is not the amount computed.
contract MockRouter {
    address public immutable quote;
    address public immutable token;

    /// Reserves, held by this contract to keep the test simple. A real pair is
    /// a separate contract; nothing in the distributor can tell the difference.
    uint256 public reserveQuote;
    uint256 public reserveToken;

    /// Taken off the output, in basis points, as a launchpad token's buy tax is.
    uint256 public buyTaxBps;
    address public taxSink;

    /// Set to a non-zero amount to hand back less than the pool arithmetic
    /// says, which is how a sandwich looks from inside the swap.
    uint256 public skimBps;

    /// A router that does not honour `amountOutMin`.
    ///
    /// **Not a hypothetical worth skipping.** A well-behaved router makes the
    /// distributor's own post-swap check unreachable, and an unreachable check
    /// is one nobody has ever seen work -- the same objection this project
    /// makes about `diag` suites that always pass. This switch is what lets
    /// `TooLittleOut` actually fire.
    bool public ignoreMin;

    error TooLittle(uint256 got, uint256 wanted);
    error BadPath();
    error Expired();

    constructor(address quote_, address token_) {
        quote = quote_;
        token = token_;
    }

    function seed(uint256 q, uint256 t) external {
        IToken(quote).transferFrom(msg.sender, address(this), q);
        IToken(token).transferFrom(msg.sender, address(this), t);
        reserveQuote += q;
        reserveToken += t;
    }

    function setBuyTax(uint256 bps, address sink) external {
        buyTaxBps = bps;
        taxSink = sink;
    }

    function setSkim(uint256 bps) external {
        skimBps = bps;
    }

    function setIgnoreMin(bool v) external {
        ignoreMin = v;
    }

    /// What `amountIn` of quote buys, before tax. The real router's formula.
    function quoteOut(uint256 amountIn) public view returns (uint256) {
        uint256 inWithFee = amountIn * 997;
        return (inWithFee * reserveToken) / (reserveQuote * 1000 + inWithFee);
    }

    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external {
        if (block.timestamp > deadline) revert Expired();
        if (path.length != 2 || path[0] != quote || path[1] != token) revert BadPath();

        IToken(quote).transferFrom(msg.sender, address(this), amountIn);
        uint256 out = quoteOut(amountIn);
        reserveQuote += amountIn;
        reserveToken -= out;

        uint256 cut = (out * buyTaxBps) / 10_000;
        uint256 skim = (out * skimBps) / 10_000;
        uint256 net = out - cut - skim;
        if (cut > 0) IToken(token).transfer(taxSink, cut);
        IToken(token).transfer(to, net);

        // **Checked against what was actually delivered, as the real one does.**
        // The whole reason this variant exists is that the caller's computed
        // output can be wrong, so the bound has to be applied after the fact.
        if (!ignoreMin && net < amountOutMin) revert TooLittle(net, amountOutMin);
    }
}
