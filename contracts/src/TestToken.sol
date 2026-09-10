// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// A stand-in for GLADOS, shaped like the real one where the shape matters.
///
/// **Not a generic mock.** GLADOS is a launchpad tax token, and the two things
/// about it that could break a distributor are that transfers can run code and
/// that some transfers take a cut. Both are here and both are switchable, so
/// the distributor is tested against the token it will actually meet rather
/// than against a well-behaved one.
///
/// Measured on-chain before writing this: a buy from the pair emits a 1% leg to
/// the token contract, a sell 3%, and a plain wallet-to-wallet transfer emits
/// one event and moves the whole amount. `taxBps` defaults to zero for that
/// reason, and the tests turn it on to check the distributor still balances
/// when the assumption is wrong.
contract TestToken {
    string public constant name = "Test GLADOS";
    string public constant symbol = "TGLADOS";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    /// Taken off every transfer, in basis points. Zero matches the real token
    /// for wallet-to-wallet, which is the only kind this contract performs.
    uint256 public taxBps;
    /// Where the cut goes, as the real one sends it to the token itself.
    address public taxSink;

    /// A reentrancy hook, because a tax token runs code on transfer and "the
    /// reentrant path is theoretical" is the assumption worth attacking.
    address public hook;
    bytes public hookData;
    bool private _inHook;

    /// If true, `transfer` returns no data at all, which is the second ERC-20
    /// convention and the reason `_call` cannot use a strict bool decode.
    bool public silent;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(uint256 supply) {
        totalSupply = supply;
        balanceOf[msg.sender] = supply;
        emit Transfer(address(0), msg.sender, supply);
    }

    function setTax(uint256 bps, address sink) external {
        taxBps = bps;
        taxSink = sink;
    }

    function setHook(address h, bytes calldata data) external {
        hook = h;
        hookData = data;
    }

    function setSilent(bool s) external {
        silent = s;
    }

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _move(msg.sender, to, amount);
        return _ret();
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 a = allowance[from][msg.sender];
        require(a >= amount, "allowance");
        if (a != type(uint256).max) allowance[from][msg.sender] = a - amount;
        _move(from, to, amount);
        return _ret();
    }

    function _ret() private view returns (bool) {
        if (silent) {
            assembly {
                return(0, 0)
            }
        }
        return true;
    }

    function _move(address from, address to, uint256 amount) private {
        require(balanceOf[from] >= amount, "balance");
        uint256 cut = (amount * taxBps) / 10_000;
        balanceOf[from] -= amount;
        balanceOf[to] += amount - cut;
        emit Transfer(from, to, amount - cut);
        if (cut > 0) {
            balanceOf[taxSink] += cut;
            emit Transfer(from, taxSink, cut);
        }
        // Fired after the balances move, as a real token's hook would be, and
        // guarded so the hook cannot recurse through its own transfer.
        if (hook != address(0) && !_inHook) {
            _inHook = true;
            (bool ok,) = hook.call(hookData);
            ok; // the hook is allowed to fail; what matters is that it ran
            _inHook = false;
        }
    }
}
