// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title SecureToken
 * @dev Advanced ERC20 token with security features including:
 * - Pausable functionality
 * - Blacklist mechanism
 * - Transaction and wallet limits
 * - Role-based minting
 * - Reentrancy protection
 * - Emergency recovery functions
 */
contract SecureToken is ERC20, Ownable, Pausable, ReentrancyGuard {
    // Mapping for blacklisted addresses
    mapping(address => bool) public isBlacklisted;
    
    // Mapping for authorized minters
    mapping(address => bool) public isMinter;

    // Transaction and wallet limits
    uint256 public maxTransactionAmount;
    uint256 public maxWalletBalance;

    // Contract metadata
    string public constant CONTRACT_VERSION = "1.1.0";
    string public contractDescription;

    // Events for tracking critical actions
    event Blacklisted(address indexed account);
    event UnBlacklisted(address indexed account);
    event MinterAdded(address indexed account);
    event MinterRemoved(address indexed account);
    event MaxTransactionAmountChanged(uint256 newAmount);
    event MaxWalletBalanceChanged(uint256 newBalance);
    event ContractDescriptionUpdated(string newDescription);
    event TokensRecovered(address indexed token, uint256 amount);
    event Initialized(uint256 initialSupply, uint256 maxTx, uint256 maxBalance);

    /**
     * @dev Modifier to check if address is not blacklisted
     */
    modifier notBlacklisted(address account) {
        require(!isBlacklisted[account], "Blacklisted address");
        _;
    }

    /**
     * @dev Modifier to restrict access to authorized minters
     */
    modifier onlyMinters() {
        require(isMinter[msg.sender], "Not a minter");
        _;
    }

    /**
     * @dev Modifier to validate amount is greater than zero
     */
    modifier validAmount(uint256 amount) {
        require(amount > 0, "Amount must be greater than zero");
        _;
    }

    /**
     * @dev Constructor to initialize the token
     * @param name Token name
     * @param symbol Token symbol
     * @param initialSupply Initial token supply
     * @param _maxTx Maximum transaction amount
     * @param _maxBalance Maximum wallet balance
     */
    constructor(
        string memory name,
        string memory symbol,
        uint256 initialSupply,
        uint256 _maxTx,
        uint256 _maxBalance
    ) ERC20(name, symbol) {
        // Validation checks
        require(initialSupply > 0, "Initial supply must be greater than 0");
        require(initialSupply <= _maxBalance, "Initial supply exceeds max wallet balance");
        require(_maxTx > 0, "Max transaction amount must be greater than 0");
        require(_maxBalance > 0, "Max wallet balance must be greater than 0");

        // Set limits
        maxTransactionAmount = _maxTx;
        maxWalletBalance = _maxBalance;

        // Mint initial supply to owner
        _mint(msg.sender, initialSupply);
        
        // Grant minter role to owner
        isMinter[msg.sender] = true;
        
        // Set contract description
        contractDescription = "Secure ERC20 Token with Advanced Security Features";
        
        // Emit initialization event
        emit Initialized(initialSupply, _maxTx, _maxBalance);
    }

    /**
     * @dev Hook that is called before any transfer of tokens
     * @param from Address sending tokens
     * @param to Address receiving tokens
     * @param amount Amount of tokens being transferred
     */
    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 amount
    ) internal override whenNotPaused notBlacklisted(from) notBlacklisted(to) {
        // Skip limits for minting and burning
        if (from != address(0) && to != address(0)) {
            require(amount <= maxTransactionAmount, "Exceeds max transaction amount");
            require(balanceOf(to) + amount <= maxWalletBalance, "Exceeds max wallet balance");
        }
        super._beforeTokenTransfer(from, to, amount);
    }

    /**
     * @dev Transfer tokens to specified address
     * @param to Address to transfer tokens to
     * @param amount Amount of tokens to transfer
     * @return Boolean indicating success
     */
    function transfer(address to, uint256 amount)
        public
        override
        whenNotPaused
        validAmount(amount)
        returns (bool)
    {
        return super.transfer(to, amount);
    }

    /**
     * @dev Transfer tokens from one address to another
     * @param from Address to transfer tokens from
     * @param to Address to transfer tokens to
     * @param amount Amount of tokens to transfer
     * @return Boolean indicating success
     */
    function transferFrom(address from, address to, uint256 amount)
        public
        override
        whenNotPaused
        validAmount(amount)
        returns (bool)
    {
        return super.transferFrom(from, to, amount);
    }

    /**
     * @dev Mint new tokens
     * @param to Address to mint tokens to
     * @param amount Amount of tokens to mint
     */
    function mint(address to, uint256 amount)
        external
        onlyMinters
        nonReentrant
        validAmount(amount)
    {
        require(to != address(0), "Cannot mint to zero address");
        require(balanceOf(to) + amount <= maxWalletBalance, "Exceeds max wallet balance");
        _mint(to, amount);
    }

    /**
     * @dev Burn tokens from caller's address
     * @param amount Amount of tokens to burn
     */
    function burn(uint256 amount) external nonReentrant validAmount(amount) {
        _burn(msg.sender, amount);
    }

    /**
     * @dev Burn tokens from specified address
     * @param account Address to burn tokens from
     * @param amount Amount of tokens to burn
     */
    function burnFrom(address account, uint256 amount) 
        external 
        nonReentrant 
        validAmount(amount) 
    {
        _spendAllowance(account, msg.sender, amount);
        _burn(account, amount);
    }

    /**
     * @dev Add address to blacklist
     * @param account Address to blacklist
     */
    function blacklist(address account) external onlyOwner {
        require(account != address(0), "Cannot blacklist zero address");
        require(!isBlacklisted[account], "Address already blacklisted");
        isBlacklisted[account] = true;
        emit Blacklisted(account);
    }

    /**
     * @dev Remove address from blacklist
     * @param account Address to unblacklist
     */
    function unBlacklist(address account) external onlyOwner {
        require(account != address(0), "Cannot unblacklist zero address");
        require(isBlacklisted[account], "Address not blacklisted");
        isBlacklisted[account] = false;
        emit UnBlacklisted(account);
    }

    /**
     * @dev Set maximum transaction amount
     * @param _maxTx New maximum transaction amount
     */
    function setMaxTransactionAmount(uint256 _maxTx) external onlyOwner {
        require(_maxTx > 0, "Max transaction amount must be greater than 0");
        maxTransactionAmount = _maxTx;
        emit MaxTransactionAmountChanged(_maxTx);
    }

    /**
     * @dev Set maximum wallet balance
     * @param _maxBalance New maximum wallet balance
     */
    function setMaxWalletBalance(uint256 _maxBalance) external onlyOwner {
        require(_maxBalance > 0, "Max wallet balance must be greater than 0");
        maxWalletBalance = _maxBalance;
        emit MaxWalletBalanceChanged(_maxBalance);
    }

    /**
     * @dev Add minter role to address
     * @param account Address to grant minter role
     */
    function addMinter(address account) external onlyOwner {
        require(account != address(0), "Cannot add zero address as minter");
        require(!isMinter[account], "Address is already a minter");
        isMinter[account] = true;
        emit MinterAdded(account);
    }

    /**
     * @dev Remove minter role from address
     * @param account Address to revoke minter role
     */
    function removeMinter(address account) external onlyOwner {
        require(account != address(0), "Cannot remove zero address");
        require(isMinter[account], "Address is not a minter");
        isMinter[account] = false;
        emit MinterRemoved(account);
    }

    /**
     * @dev Update contract description
     * @param newDescription New contract description
     */
    function updateContractDescription(string memory newDescription) external onlyOwner {
        require(bytes(newDescription).length > 0, "Description cannot be empty");
        contractDescription = newDescription;
        emit ContractDescriptionUpdated(newDescription);
    }

    /**
     * @dev Recover accidentally sent ERC20 tokens
     * @param tokenAddress Address of token to recover
     * @param tokenAmount Amount of tokens to recover
     */
    function recoverERC20(address tokenAddress, uint256 tokenAmount) external onlyOwner {
        require(tokenAddress != address(this), "Cannot recover this token");
        require(tokenAmount > 0, "Amount must be greater than zero");
        
        IERC20 token = IERC20(tokenAddress);
        uint256 balance = token.balanceOf(address(this));
        require(balance >= tokenAmount, "Insufficient token balance");
        
        token.transfer(owner(), tokenAmount);
        emit TokensRecovered(tokenAddress, tokenAmount);
    }

    /**
     * @dev Withdraw accidentally sent ETH
     */
    function withdrawETH() external onlyOwner {
        payable(owner()).transfer(address(this).balance);
    }

    /**
     * @dev Pause all token transfers
     */
    function pause() external onlyOwner {
        _pause();
    }

    /**
     * @dev Unpause all token transfers
     */
    function unpause() external onlyOwner {
        _unpause();
    }
}