// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/**
 * @title SafeToken
 * @notice A deliberately secure ERC-20-like token for contrast with VulnerableVault.
 */
contract SafeToken {
    string  public name     = "SafeToken";
    string  public symbol   = "SAFE";
    uint8   public decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256)                     private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;

    address public owner;
    bool    private _locked;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event OwnershipTransferred(address indexed previous, address indexed next);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier noReentrant() {
        require(!_locked, "Reentrant call");
        _locked = true;
        _;
        _locked = false;
    }

    constructor(address _owner, uint256 _initial) {
        require(_owner != address(0), "Zero address");
        owner = _owner;
        _mint(_owner, _initial);
    }

    function transfer(address to, uint256 value) public returns (bool) {
        _transfer(msg.sender, to, value);
        return true;
    }

    function approve(address spender, uint256 value) public returns (bool) {
        _allowances[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) public returns (bool) {
        require(_allowances[from][msg.sender] >= value, "Allowance exceeded");
        _allowances[from][msg.sender] -= value;
        _transfer(from, to, value);
        return true;
    }

    function mint(address to, uint256 value) public onlyOwner {
        _mint(to, value);
    }

    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0), "Zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function _transfer(address from, address to, uint256 value) internal {
        require(from != address(0) && to != address(0), "Zero address");
        require(_balances[from] >= value, "Insufficient balance");
        _balances[from] -= value;
        _balances[to]   += value;
        emit Transfer(from, to, value);
    }

    function _mint(address to, uint256 value) internal {
        require(to != address(0), "Zero address");
        totalSupply       += value;
        _balances[to]     += value;
        emit Transfer(address(0), to, value);
    }

    function balanceOf(address account) public view returns (uint256) {
        return _balances[account];
    }
}
