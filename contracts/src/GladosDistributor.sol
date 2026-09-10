// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title The claim contract for the GLaDOS mining pool's GLADOS reward.
///
/// @notice Layer 1 of this pool never holds a miner's coins: they are paid by
/// the upstream chain, directly, in what they mined. This contract is Layer 2,
/// and it distributes the *operator's own* fee revenue, converted to GLADOS.
/// Converting your own money is not a regulated service; holding somebody
/// else's is, which is why these are two layers and not one.
///
/// @dev The design is a Merkle distributor per epoch. What it does differently
/// from the usual one, and why:
///
/// **The gate is per epoch and immutable once the epoch exists.** A single
/// mutable `minimumBalance` would let the operator change the rules for work
/// already done. Here the threshold is fixed at the moment the root is
/// published, so an epoch's terms are as final as its amounts, and changing
/// the gate is visible as a new epoch rather than as a silent state write.
///
/// **The balance check happens at claim time, not at share time.** That is the
/// point of putting it here at all: `docs/token/index.html` argues that a
/// balance check compiled into a ring-0 kernel is one edit away from being
/// deleted, and that a check in the claim contract is not. It also means
/// selling below the gate between mining and claiming forfeits the claim, which
/// is intended -- the gate is a holding requirement, not an entry fee.
///
/// **Amounts are taken as received rather than as requested.** GLADOS is a tax
/// token. Wallet-to-wallet transfers are untaxed -- verified on-chain, by
/// reading `Transfer` logs and finding plain transfers that move an identical
/// amount with no second event, where a buy from the pair emits a 1% tax leg
/// and a sell 3% -- but a contract that *assumes* that and is wrong hands out
/// claims it cannot pay, and the failure lands on whoever claims last. So the
/// balance is measured either side of the transfer and the epoch records what
/// actually arrived.
/// The only ERC-20 call this contract makes through a typed interface.
///
/// `balanceOf` is a view and its return is unambiguous, so it can be typed.
/// The two that move tokens go through `_call` instead, because the standard
/// says they return `bool` and enough tokens return nothing that a strict
/// decode reverts on transfers that actually succeeded.
interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
}

/// Uniswap V2's fee-on-transfer swap, which is the only one that works here.
///
/// The plain `swapExactTokensForTokens` asserts the amounts it computed up
/// front actually arrive, and a token that takes a cut makes that assertion
/// false -- the swap reverts on a tax token rather than handling one. The
/// `SupportingFeeOnTransferTokens` variant measures balances instead, which is
/// the same bargain `openEpoch` makes with `funded`.
interface IUniswapV2Router {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external;
}

contract GladosDistributor {
    /// How an epoch pays.
    ///
    /// **`Market` is not a better `Direct`, it is a different trade**, and the
    /// arithmetic decides rather than taste. A swap costs about $0.048 of gas
    /// on this chain against $0.029 for a transfer, and a claim is worth what
    /// the fee pot divided by the miners says it is worth: $0.0021 each over a
    /// 36-hour event, where the gas is 2,286% of the reward, and $0.51 each on
    /// a yearly epoch with a thousand miners, where it is 9%.
    ///
    /// What `Market` buys is that every claim is a real trade -- it moves the
    /// price, it pays the token's own buy tax into dividends, liquidity and the
    /// burn, and it is visible on-chain as a buy rather than as an operator
    /// handing out tokens they converted somewhere nobody watched. What it
    /// costs is gas per claim and a price that moves between the first
    /// claimant and the last.
    enum Mode {
        /// The epoch holds the reward token. A claim transfers it.
        Direct,
        /// The epoch holds an input token. A claim swaps it on the market and
        /// the reward token goes straight to the claimant.
        Market
    }

    struct Epoch {
        /// Merkle root over `(account, amount)` leaves.
        bytes32 root;
        /// What the contract actually received when the epoch was opened.
        uint256 funded;
        /// Sum of what has been claimed so far.
        uint256 claimed;
        /// Minimum GLADOS balance a claimant must hold, checked at claim time.
        uint256 gate;
        /// After this, the operator may take back what nobody claimed.
        uint64 deadline;
        /// Whether the remainder has already gone back.
        bool reclaimed;
        /// How this epoch pays. Fixed when the epoch opens, like the gate.
        Mode mode;
    }

    /// The token being distributed. Immutable: a distributor that could be
    /// repointed at a different token is a different contract wearing this
    /// one's address.
    address public immutable token;

    /// Who may open epochs and reclaim expired remainders. Immutable for the
    /// same reason -- there is no upgrade path and no admin key rotation, so
    /// the whole of what this address can do is visible in two functions.
    address public immutable operator;

    /// The market. Immutable: a distributor that could be repointed at a
    /// different router is one that could route a claim into a pool the
    /// operator controls. Zero disables `Market` epochs entirely, which is the
    /// right configuration on a chain with no pool worth using.
    address public immutable router;

    /// What a `Market` epoch is funded in. WETH here, because that is what the
    /// GLADOS pool is quoted against -- read from the token's own
    /// `quoteToken()` rather than chosen, so the path is the pool that exists.
    address public immutable quote;

    Epoch[] private _epochs;

    /// `epoch => account => claimed`. By address rather than by a bitmap over
    /// leaf indices: the index form saves gas and buys a way for two leaves to
    /// name one account, and on a chain where a claim costs about three cents
    /// that is the wrong side of the trade.
    mapping(uint256 => mapping(address => bool)) public hasClaimed;

    event EpochOpened(uint256 indexed epoch, bytes32 root, uint256 funded, uint256 gate, uint64 deadline, Mode mode);
    /// `amount` is the leaf and `received` is what reached the claimant. Equal
    /// under `Direct`; under `Market` the leaf is denominated in `quote`, so
    /// the two together are the record of what the market actually gave --
    /// which is the whole point of paying through one.
    event Claimed(uint256 indexed epoch, address indexed account, uint256 amount, uint256 received);
    event Reclaimed(uint256 indexed epoch, uint256 amount);

    error NotOperator();
    error NoRoot();
    error NothingFunded();
    error DeadlineInPast();
    error NoSuchEpoch();
    error AlreadyClaimed();
    error BadProof();
    error BelowGate(uint256 held, uint256 needed);
    error EpochClosed();
    error EpochOpen();
    error AlreadyReclaimed();
    error Insolvent(uint256 want, uint256 have);
    error TransferFailed();
    error NoMarket();
    error WrongMode();
    error NoSlippageBound();
    error TooLittleOut(uint256 got, uint256 wanted);

    constructor(address token_, address operator_, address router_, address quote_) {
        require(token_ != address(0) && operator_ != address(0), "zero address");
        // `router` and `quote` may both be zero, which simply means this
        // distributor cannot open `Market` epochs. Requiring them would make
        // the contract undeployable on a chain where the pool does not exist
        // yet, which is a state this project has been in twice.
        require((router_ == address(0)) == (quote_ == address(0)), "router and quote go together");
        token = token_;
        operator = operator_;
        router = router_;
        quote = quote_;
    }

    modifier onlyOperator() {
        if (msg.sender != operator) revert NotOperator();
        _;
    }

    /// Publish a root and fund it in one transaction.
    ///
    /// One call rather than "create then fund", because an epoch that exists
    /// and is not funded is a set of claims that revert, and the person who
    /// finds out is a miner rather than the operator.
    ///
    /// The operator must have approved this contract for `amount` first.
    function openEpoch(bytes32 root, uint256 amount, uint256 gate, uint64 deadline)
        external
        onlyOperator
        returns (uint256 epochId)
    {
        if (root == bytes32(0)) revert NoRoot();
        if (amount == 0) revert NothingFunded();
        if (deadline <= block.timestamp) revert DeadlineInPast();

        // Measured rather than assumed. See the note on tax tokens above.
        uint256 before = IERC20(token).balanceOf(address(this));
        _pull(msg.sender, amount);
        uint256 got = IERC20(token).balanceOf(address(this)) - before;
        if (got == 0) revert NothingFunded();

        epochId = _epochs.length;
        _epochs.push(Epoch({
            root: root,
            funded: got,
            claimed: 0,
            gate: gate,
            deadline: deadline,
            reclaimed: false,
            mode: Mode.Direct
        }));
        emit EpochOpened(epochId, root, got, gate, deadline, Mode.Direct);
    }

    /// Open an epoch that pays by buying on the market, one buy per claim.
    ///
    /// Funded in `quote` rather than in the reward token: the operator never
    /// converts anything, so there is no conversion rate for anybody to have to
    /// trust. Each claimant's own transaction is the trade, at the price the
    /// pool has at that moment, and the reward token goes from the pair to them
    /// -- which means the token's buy tax applies and feeds whatever the token
    /// does with it.
    ///
    /// **The leaf is denominated in `quote`, and that has a consequence worth
    /// stating before somebody discovers it.** Every claim moves the price, so
    /// the first claimant gets more reward token per unit of quote than the
    /// last. That is a race, it is inherent to paying through a market rather
    /// than around one, and it is the reason `Direct` still exists.
    function openEpochOnMarket(bytes32 root, uint256 amount, uint256 gate, uint64 deadline)
        external
        onlyOperator
        returns (uint256 epochId)
    {
        if (router == address(0)) revert NoMarket();
        if (root == bytes32(0)) revert NoRoot();
        if (amount == 0) revert NothingFunded();
        if (deadline <= block.timestamp) revert DeadlineInPast();

        uint256 before = IERC20(quote).balanceOf(address(this));
        _move(quote, abi.encodeWithSelector(0x23b872dd, msg.sender, address(this), amount));
        uint256 got = IERC20(quote).balanceOf(address(this)) - before;
        if (got == 0) revert NothingFunded();

        epochId = _epochs.length;
        _epochs.push(Epoch({
            root: root,
            funded: got,
            claimed: 0,
            gate: gate,
            deadline: deadline,
            reclaimed: false,
            mode: Mode.Market
        }));
        emit EpochOpened(epochId, root, got, gate, deadline, Mode.Market);
    }

    /// Claim one epoch's allocation.
    ///
    /// `amount` and `proof` come from the published root; anybody can compute
    /// them from the share log, which is the point of publishing it.
    function claim(uint256 epochId, uint256 amount, bytes32[] calldata proof) external {
        Epoch storage e = _admit(epochId, amount, proof);
        if (e.mode != Mode.Direct) revert WrongMode();
        _send(token, msg.sender, amount);
        emit Claimed(epochId, msg.sender, amount, amount);
    }

    /// Claim by buying on the market, in the claimant's own transaction.
    ///
    /// `minOut` is the claimant's slippage bound and must be non-zero. A swap
    /// with no bound on a pool this thin is a sandwich waiting to happen, and
    /// zero is never the right answer -- refusing it costs a revert and saves
    /// somebody their reward.
    function claimOnMarket(uint256 epochId, uint256 amount, bytes32[] calldata proof, uint256 minOut)
        external
        returns (uint256 received)
    {
        if (minOut == 0) revert NoSlippageBound();
        Epoch storage e = _admit(epochId, amount, proof);
        if (e.mode != Mode.Market) revert WrongMode();

        address[] memory path = new address[](2);
        path[0] = quote;
        path[1] = token;

        // **Approved for exactly this swap and left at zero afterwards.** A
        // standing max allowance to the router would be a smaller contract and
        // a larger blast radius, and nothing here needs the allowance to
        // outlive the call.
        _approve(quote, router, amount);
        uint256 before = IERC20(token).balanceOf(msg.sender);
        IUniswapV2Router(router).swapExactTokensForTokensSupportingFeeOnTransferTokens(
            amount, minOut, path, msg.sender, block.timestamp
        );
        _approve(quote, router, 0);

        // Measured on the claimant rather than trusted from the router, which
        // is the rule `openEpoch` already follows about `funded`: this variant
        // returns nothing, and a tax token means what arrives is not what was
        // quoted.
        received = IERC20(token).balanceOf(msg.sender) - before;
        if (received < minOut) revert TooLittleOut(received, minOut);
        emit Claimed(epochId, msg.sender, amount, received);
    }

    /// Everything both claim paths must do, in one place.
    ///
    /// Written once because two copies of a gate check is how one of them ends
    /// up a `>` where the other is a `>=`. It marks the claim *before*
    /// returning, so both callers are reentrancy-safe by the time they touch a
    /// token.
    function _admit(uint256 epochId, uint256 amount, bytes32[] calldata proof)
        private
        returns (Epoch storage e)
    {
        if (epochId >= _epochs.length) revert NoSuchEpoch();
        e = _epochs[epochId];
        if (block.timestamp > e.deadline) revert EpochClosed();
        if (hasClaimed[epochId][msg.sender]) revert AlreadyClaimed();

        // **The gate, and the whole reason this lives on-chain.**
        uint256 held = IERC20(token).balanceOf(msg.sender);
        if (held < e.gate) revert BelowGate(held, e.gate);

        if (!_verify(proof, e.root, _leaf(msg.sender, amount))) revert BadProof();

        // A root that promises more than the epoch holds is an operator error,
        // caught here rather than by the last claimant getting a failed
        // transfer they cannot explain.
        uint256 left = e.funded - e.claimed;
        if (amount > left) revert Insolvent(amount, left);

        // Effects before interaction. GLADOS is a tax token and tax tokens run
        // code on transfer, so the reentrant path is real rather than
        // theoretical -- and with this ordering a reentrant call finds
        // `hasClaimed` already true.
        hasClaimed[epochId][msg.sender] = true;
        e.claimed += amount;
    }

    /// Take back what nobody claimed, once the epoch has closed.
    ///
    /// **This is the one power the operator has over funds already committed,
    /// and it is bounded in three ways**: only after a deadline fixed when the
    /// epoch was opened, only the unclaimed remainder of that epoch, and only
    /// once. Without it, tokens allocated to an address that lost its key are
    /// removed from supply forever with nobody having decided that; with it
    /// unbounded, the epoch would be a promise the operator could withdraw.
    function reclaim(uint256 epochId) external onlyOperator returns (uint256 amount) {
        if (epochId >= _epochs.length) revert NoSuchEpoch();
        Epoch storage e = _epochs[epochId];
        if (block.timestamp <= e.deadline) revert EpochOpen();
        if (e.reclaimed) revert AlreadyReclaimed();

        amount = e.funded - e.claimed;
        e.reclaimed = true;
        // The epoch's own asset: a `Market` epoch holds `quote`, and sending it
        // back as `token` would be sending tokens it does not have.
        if (amount > 0) _send(e.mode == Mode.Direct ? token : quote, operator, amount);
        emit Reclaimed(epochId, amount);
    }

    // ---------------------------------------------------------------- views

    function epochCount() external view returns (uint256) {
        return _epochs.length;
    }

    function epochs(uint256 id) external view returns (Epoch memory) {
        if (id >= _epochs.length) revert NoSuchEpoch();
        return _epochs[id];
    }

    /// What a claim would do, without doing it. Every reason a claim can fail,
    /// answered as a string, because the thing a miner needs is not a revert
    /// selector -- it is to know whether the problem is their balance, their
    /// proof, or the clock.
    function checkClaim(uint256 epochId, address account, uint256 amount, bytes32[] calldata proof)
        external
        view
        returns (bool ok, string memory reason)
    {
        if (epochId >= _epochs.length) return (false, "no such epoch");
        Epoch storage e = _epochs[epochId];
        if (block.timestamp > e.deadline) return (false, "epoch closed");
        if (hasClaimed[epochId][account]) return (false, "already claimed");
        if (IERC20(token).balanceOf(account) < e.gate) return (false, "below the gate");
        if (!_verify(proof, e.root, _leaf(account, amount))) return (false, "proof does not match the root");
        if (amount > e.funded - e.claimed) return (false, "epoch is short");
        return (true, "");
    }

    /// The leaf preimage, exposed so an off-chain builder can be checked
    /// against this contract rather than against its own idea of the format.
    function leafOf(address account, uint256 amount) external pure returns (bytes32) {
        return _leaf(account, amount);
    }

    /// Verification, exposed for the same reason and it is the more important
    /// of the two.
    ///
    /// A builder checked only against itself is checked against nothing: its
    /// proofs verify under its own rules whatever those rules are. The tree
    /// tests were doing exactly that until this existed -- folding a JS proof
    /// with JS hashing and comparing to a JS root, which would pass with the
    /// handedness reversed, the leaf hashed once, or the odd node duplicated.
    /// This makes the arbiter the bytecode that will actually hold the tokens.
    function verifyProof(bytes32[] calldata proof, bytes32 root, address account, uint256 amount)
        external
        pure
        returns (bool)
    {
        return _verify(proof, root, _leaf(account, amount));
    }

    // ------------------------------------------------------------ internals

    /// **Double-hashed**, which is not decoration.
    ///
    /// With sorted-pair hashing an internal node is `keccak256` of 64 bytes. A
    /// singly-hashed leaf over `abi.encode(address, uint256)` is also 64 bytes,
    /// so a crafted "leaf" could be presented as an internal node and a proof
    /// forged around it. Hashing twice makes a leaf preimage 32 bytes and the
    /// two domains cannot collide.
    function _leaf(address account, uint256 amount) private pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encode(account, amount))));
    }

    /// Sorted-pair Merkle verification. Sorted so a proof carries no direction
    /// bits and the builder cannot disagree with the verifier about handedness,
    /// which is the mistake that produces a root that is wrong only sometimes.
    function _verify(bytes32[] calldata proof, bytes32 root, bytes32 leaf) private pure returns (bool) {
        bytes32 h = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 p = proof[i];
            h = h <= p ? keccak256(abi.encode(h, p)) : keccak256(abi.encode(p, h));
        }
        return h == root;
    }

    function _pull(address from, uint256 amount) private {
        _move(token, abi.encodeWithSelector(0x23b872dd, from, address(this), amount));
    }

    function _send(address asset, address to, uint256 amount) private {
        _move(asset, abi.encodeWithSelector(0xa9059cbb, to, amount));
    }

    function _approve(address asset, address spender, uint256 amount) private {
        _move(asset, abi.encodeWithSelector(0x095ea7b3, spender, amount));
    }

    /// A transfer that accepts both conventions.
    ///
    /// The ERC-20 standard says `transfer` returns `bool`; enough tokens return
    /// nothing that a strict decode reverts on transfers that succeeded. Empty
    /// return data is treated as success and any other return must decode to
    /// true, which is the ordinary safe-transfer rule written out rather than
    /// imported.
    function _move(address asset, bytes memory data) private {
        (bool okCall, bytes memory ret) = asset.call(data);
        if (!okCall) revert TransferFailed();
        if (ret.length != 0 && !abi.decode(ret, (bool))) revert TransferFailed();
    }
}
