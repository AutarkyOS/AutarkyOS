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

contract GladosDistributor {
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
    }

    /// The token being distributed. Immutable: a distributor that could be
    /// repointed at a different token is a different contract wearing this
    /// one's address.
    address public immutable token;

    /// Who may open epochs and reclaim expired remainders. Immutable for the
    /// same reason -- there is no upgrade path and no admin key rotation, so
    /// the whole of what this address can do is visible in two functions.
    address public immutable operator;

    Epoch[] private _epochs;

    /// `epoch => account => claimed`. By address rather than by a bitmap over
    /// leaf indices: the index form saves gas and buys a way for two leaves to
    /// name one account, and on a chain where a claim costs about three cents
    /// that is the wrong side of the trade.
    mapping(uint256 => mapping(address => bool)) public hasClaimed;

    event EpochOpened(uint256 indexed epoch, bytes32 root, uint256 funded, uint256 gate, uint64 deadline);
    event Claimed(uint256 indexed epoch, address indexed account, uint256 amount);
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

    constructor(address token_, address operator_) {
        require(token_ != address(0) && operator_ != address(0), "zero address");
        token = token_;
        operator = operator_;
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
            reclaimed: false
        }));
        emit EpochOpened(epochId, root, got, gate, deadline);
    }

    /// Claim one epoch's allocation.
    ///
    /// `amount` and `proof` come from the published root; anybody can compute
    /// them from the share log, which is the point of publishing it.
    function claim(uint256 epochId, uint256 amount, bytes32[] calldata proof) external {
        if (epochId >= _epochs.length) revert NoSuchEpoch();
        Epoch storage e = _epochs[epochId];
        if (block.timestamp > e.deadline) revert EpochClosed();
        if (hasClaimed[epochId][msg.sender]) revert AlreadyClaimed();

        // **The gate, and the whole reason this lives on-chain.**
        uint256 held = IERC20(token).balanceOf(msg.sender);
        if (held < e.gate) revert BelowGate(held, e.gate);

        if (!_verify(proof, e.root, _leaf(msg.sender, amount))) revert BadProof();

        // A root that promises more than the epoch holds is an operator error,
        // and it is caught here rather than by the last claimant getting a
        // failed transfer they cannot explain.
        uint256 left = e.funded - e.claimed;
        if (amount > left) revert Insolvent(amount, left);

        // Effects before interaction. GLADOS is a tax token and tax tokens run
        // code on transfer, so the reentrant path is real rather than
        // theoretical -- and with this ordering a reentrant call finds
        // `hasClaimed` already true.
        hasClaimed[epochId][msg.sender] = true;
        e.claimed += amount;

        _send(msg.sender, amount);
        emit Claimed(epochId, msg.sender, amount);
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
        if (amount > 0) _send(operator, amount);
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
        _call(abi.encodeWithSelector(0x23b872dd, from, address(this), amount));
    }

    function _send(address to, uint256 amount) private {
        _call(abi.encodeWithSelector(0xa9059cbb, to, amount));
    }

    /// A transfer that accepts both conventions.
    ///
    /// The ERC-20 standard says `transfer` returns `bool`; enough tokens return
    /// nothing that a strict decode reverts on transfers that succeeded. Empty
    /// return data is treated as success and any other return must decode to
    /// true, which is the ordinary safe-transfer rule written out rather than
    /// imported.
    function _call(bytes memory data) private {
        (bool okCall, bytes memory ret) = token.call(data);
        if (!okCall) revert TransferFailed();
        if (ret.length != 0 && !abi.decode(ret, (bool))) revert TransferFailed();
    }
}
