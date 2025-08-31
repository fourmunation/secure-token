# 🔐 Secure Token Contract

Advanced ERC-20 token implementation with comprehensive security features for DeFi applications.

## 🌟 Features

- ** ERC-20 Compliance**
- **Pausable Functionality** - Emergency pause/unpause transfers
- **Blacklist Mechanism** - Block malicious addresses
- **Transaction Limits** - Max transaction amount control
- **Wallet Balance Limits** - Max wallet balance control
- **Role-Based Minting** - Authorized minter system
- **Reentrancy Protection** - Built-in security guards
- **Emergency Recovery** - Recover stuck tokens/ETH
- **Comprehensive Events** - Full audit trail

## 🛡️ Security Features

- Zero address validation
- Amount validation (must be > 0)
- Duplicate operation prevention
- Balance verification before recovery
- Blacklist/whitelist state management
- Gas optimization
- Input sanitization

## 🚀 Deployment

```bash
# Install dependencies
npm install

# Compile contracts
npx hardhat compile

# Run tests
npx hardhat test

# Deploy to network
npx hardhat run scripts/deploy.js --network [network-name]
