// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title Cross-Chain Bridge (Advanced)
 * @dev Advanced cross-chain bridge contract for secure token transfers
 * @notice This contract enables decentralized token transfers between blockchain networks
 * @author Bridge Development Team
 */

// ERC20 Interface
interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

contract CrossChainBridge {
    
    // Contract owner
    address public owner;
    
    // Reentrancy protection
    bool private locked;
    
    // Events
    event TokensLocked(
        address indexed user,
        address indexed token,
        uint256 amount,
        uint256 indexed destinationChainId,
        bytes32 transactionHash,
        uint256 timestamp
    );
    
    event TokensUnlocked(
        address indexed user,
        address indexed token,
        uint256 amount,
        bytes32 indexed sourceTransactionHash,
        uint256 sourceChainId,
        uint256 timestamp
    );
    
    event ValidatorAdded(address indexed validator, uint256 timestamp);
    event ValidatorRemoved(address indexed validator, uint256 timestamp);
    event TransactionValidated(bytes32 indexed transactionHash, address indexed validator);
    event ConsensusReached(bytes32 indexed transactionHash, uint256 validatorCount);

    // Structures
    struct BridgeTransaction {
        address user;
        address token;
        uint256 amount;
        uint256 destinationChainId;
        uint256 sourceChainId;
        bool processed;
        uint256 timestamp;
        uint256 validatorCount;
    }

    struct UnlockRequest {
        address user;
        address token;
        uint256 amount;
        bytes32 sourceTransactionHash;
        uint256 sourceChainId;
        bool executed;
        uint256 timestamp;
        uint256 validatorApprovals;
    }

    // State variables
    mapping(address => bool) public validators;
    mapping(bytes32 => BridgeTransaction) public bridgeTransactions;
    mapping(bytes32 => UnlockRequest) public unlockRequests;
    mapping(bytes32 => mapping(address => bool)) public hasValidatorSigned;
    mapping(address => bool) public supportedTokens;
    mapping(address => uint256) public tokenLiquidity;
    
    address[] public validatorList;
    uint256 public requiredValidators;
    uint256 public currentChainId;
    uint256 public totalTransactions;
    uint256 public totalValueLocked;
    
    // Constants
    uint256 public constant MIN_VALIDATORS = 3;
    uint256 public constant MAX_VALIDATORS = 21;

    // Modifiers
    modifier onlyOwner() {
        require(msg.sender == owner, "Unauthorized: Only owner");
        _;
    }

    modifier nonReentrant() {
        require(!locked, "ReentrancyGuard: reentrant call");
        locked = true;
        _;
        locked = false;
    }

    modifier onlyValidator() {
        require(validators[msg.sender], "Unauthorized: Only validator");
        _;
    }

    modifier validToken(address token) {
        require(supportedTokens[token], "Token not supported");
        require(token != address(0), "Invalid token address");
        _;
    }

    modifier validAmount(uint256 amount) {
        require(amount > 0, "Amount must be greater than zero");
        _;
    }

    // Constructor
    constructor(uint256 _chainId, address[] memory _initialValidators) {
        require(_initialValidators.length >= MIN_VALIDATORS, "Insufficient initial validators");
        require(_initialValidators.length <= MAX_VALIDATORS, "Too many initial validators");
        
        owner = msg.sender;
        currentChainId = _chainId;
        requiredValidators = (_initialValidators.length * 2) / 3 + 1; // 2/3 + 1 majority
        
        // Add initial validators
        for (uint256 i = 0; i < _initialValidators.length; i++) {
            require(_initialValidators[i] != address(0), "Invalid validator address");
            require(!validators[_initialValidators[i]], "Duplicate validator");
            
            validators[_initialValidators[i]] = true;
            validatorList.push(_initialValidators[i]);
            emit ValidatorAdded(_initialValidators[i], block.timestamp);
        }
    }

    /**
     * @dev Core Function 1: Lock tokens for cross-chain transfer
     * @param token Address of the token to lock
     * @param amount Amount of tokens to lock
     * @param destinationChainId Target blockchain network ID
     * @notice Users must approve this contract to spend tokens before calling
     */
    function lockTokens(
        address token,
        uint256 amount,
        uint256 destinationChainId
    ) 
        external 
        nonReentrant 
        validToken(token) 
        validAmount(amount) 
        returns (bytes32 transactionHash) 
    {
        require(destinationChainId != currentChainId, "Cannot bridge to same chain");
        require(destinationChainId > 0, "Invalid destination chain ID");
        
        // Check user balance and allowance
        IERC20 tokenContract = IERC20(token);
        require(tokenContract.balanceOf(msg.sender) >= amount, "Insufficient token balance");
        require(tokenContract.allowance(msg.sender, address(this)) >= amount, "Insufficient allowance");
        
        // Transfer tokens to bridge contract
        require(tokenContract.transferFrom(msg.sender, address(this), amount), "Token transfer failed");
        
        // Generate unique transaction hash
        transactionHash = keccak256(
            abi.encodePacked(
                msg.sender,
                token,
                amount,
                destinationChainId,
                currentChainId,
                block.timestamp,
                block.number,
                totalTransactions
            )
        );
        
        // Store bridge transaction
        bridgeTransactions[transactionHash] = BridgeTransaction({
            user: msg.sender,
            token: token,
            amount: amount,
            destinationChainId: destinationChainId,
            sourceChainId: currentChainId,
            processed: false,
            timestamp: block.timestamp,
            validatorCount: 0
        });
        
        // Update statistics
        totalTransactions++;
        totalValueLocked += amount;
        tokenLiquidity[token] += amount;
        
        emit TokensLocked(
            msg.sender, 
            token, 
            amount, 
            destinationChainId, 
            transactionHash, 
            block.timestamp
        );
        
        return transactionHash;
    }

    /**
     * @dev Core Function 2: Unlock tokens after cross-chain verification
     * @param user Address of the recipient
     * @param token Address of the token to unlock
     * @param amount Amount of tokens to unlock
     * @param sourceTransactionHash Hash from the source chain transaction
     * @param sourceChainId Source blockchain network ID
     * @param validatorSignatures Array of validator signatures approving the unlock
     */
    function unlockTokens(
        address user,
        address token,
        uint256 amount,
        bytes32 sourceTransactionHash,
        uint256 sourceChainId,
        bytes[] memory validatorSignatures
    ) 
        external 
        nonReentrant 
        validToken(token) 
        validAmount(amount) 
        returns (bool success) 
    {
        require(user != address(0), "Invalid recipient address");
        require(sourceChainId != currentChainId, "Invalid source chain");
        require(sourceChainId > 0, "Invalid source chain ID");
        require(validatorSignatures.length >= requiredValidators, "Insufficient validator signatures");
        
        // Generate unlock request hash
        bytes32 unlockHash = keccak256(
            abi.encodePacked(
                user,
                token,
                amount,
                sourceTransactionHash,
                sourceChainId,
                currentChainId
            )
        );
        
        require(!unlockRequests[unlockHash].executed, "Unlock already executed");
        
        // Verify validator signatures
        uint256 validSignatures = 0;
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                unlockHash
            )
        );
        
        for (uint256 i = 0; i < validatorSignatures.length && validSignatures < requiredValidators; i++) {
            address signer = recoverSigner(messageHash, validatorSignatures[i]);
            
            if (validators[signer] && !hasValidatorSigned[unlockHash][signer]) {
                hasValidatorSigned[unlockHash][signer] = true;
                validSignatures++;
            }
        }
        
        require(validSignatures >= requiredValidators, "Insufficient valid signatures");
        
        // Check contract has enough tokens
        IERC20 tokenContract = IERC20(token);
        require(tokenContract.balanceOf(address(this)) >= amount, "Insufficient contract balance");
        require(tokenLiquidity[token] >= amount, "Insufficient token liquidity");
        
        // Store unlock request
        unlockRequests[unlockHash] = UnlockRequest({
            user: user,
            token: token,
            amount: amount,
            sourceTransactionHash: sourceTransactionHash,
            sourceChainId: sourceChainId,
            executed: true,
            timestamp: block.timestamp,
            validatorApprovals: validSignatures
        });
        
        // Update liquidity tracking
        tokenLiquidity[token] -= amount;
        
        // Transfer tokens to user
        require(tokenContract.transfer(user, amount), "Token transfer failed");
        
        emit TokensUnlocked(
            user, 
            token, 
            amount, 
            sourceTransactionHash, 
            sourceChainId, 
            block.timestamp
        );
        
        return true;
    }

    /**
     * @dev Core Function 3: Validator consensus mechanism for transaction verification  
     * @param transactionHash Hash of the transaction to validate
     * @param isValid Whether the validator approves this transaction
     * @notice Only authorized validators can call this function
     */
    function validateTransaction(
        bytes32 transactionHash,
        bool isValid
    ) 
        external 
        onlyValidator 
        returns (bool consensusReached) 
    {
        require(transactionHash != bytes32(0), "Invalid transaction hash");
        require(!hasValidatorSigned[transactionHash][msg.sender], "Validator already signed");
        
        BridgeTransaction storage transaction = bridgeTransactions[transactionHash];
        require(transaction.user != address(0), "Transaction does not exist");
        require(!transaction.processed, "Transaction already processed");
        
        // Record validator decision
        hasValidatorSigned[transactionHash][msg.sender] = true;
        
        if (isValid) {
            transaction.validatorCount++;
            emit TransactionValidated(transactionHash, msg.sender);
            
            // Check if consensus reached
            if (transaction.validatorCount >= requiredValidators) {
                transaction.processed = true;
                emit ConsensusReached(transactionHash, transaction.validatorCount);
                return true;
            }
        }
        
        return false;
    }

    // Utility function for signature recovery
    function recoverSigner(bytes32 hash, bytes memory signature) internal pure returns (address) {
        if (signature.length != 65) {
            return address(0);
        }
        
        bytes32 r;
        bytes32 s;
        uint8 v;
        
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        
        if (v < 27) {
            v += 27;
        }
        
        if (v != 27 && v != 28) {
            return address(0);
        }
        
        return ecrecover(hash, v, r, s);
    }

    // Administrative functions
    function addValidator(address validator) external onlyOwner {
        require(validator != address(0), "Invalid validator address");
        require(!validators[validator], "Validator already exists");
        require(validatorList.length < MAX_VALIDATORS, "Maximum validators reached");
        
        validators[validator] = true;
        validatorList.push(validator);
        
        // Update required validators (2/3 majority + 1)
        requiredValidators = (validatorList.length * 2) / 3 + 1;
        
        emit ValidatorAdded(validator, block.timestamp);
    }

    function removeValidator(address validator) external onlyOwner {
        require(validators[validator], "Validator does not exist");
        require(validatorList.length > MIN_VALIDATORS, "Cannot go below minimum validators");
        
        validators[validator] = false;
        
        // Remove from array
        for (uint256 i = 0; i < validatorList.length; i++) {
            if (validatorList[i] == validator) {
                validatorList[i] = validatorList[validatorList.length - 1];
                validatorList.pop();
                break;
            }
        }
        
        // Update required validators
        requiredValidators = (validatorList.length * 2) / 3 + 1;
        
        emit ValidatorRemoved(validator, block.timestamp);
    }

    function addSupportedToken(address token) external onlyOwner {
        require(token != address(0), "Invalid token address");
        require(!supportedTokens[token], "Token already supported");
        
        supportedTokens[token] = true;
    }

    function removeSupportedToken(address token) external onlyOwner {
        require(supportedTokens[token], "Token not supported");
        require(tokenLiquidity[token] == 0, "Token has locked liquidity");
        
        supportedTokens[token] = false;
    }

    // View functions
    function getValidators() external view returns (address[] memory) {
        return validatorList;
    }

    function getValidatorCount() external view returns (uint256) {
        return validatorList.length;
    }

    function isTransactionProcessed(bytes32 transactionHash) external view returns (bool) {
        return bridgeTransactions[transactionHash].processed;
    }

    function getTransactionValidatorCount(bytes32 transactionHash) external view returns (uint256) {
        return bridgeTransactions[transactionHash].validatorCount;
    }

    function getBridgeStats() external view returns (
        uint256 _totalTransactions,
        uint256 _totalValueLocked,
        uint256 _validatorCount,
        uint256 _requiredValidators
    ) {
        return (totalTransactions, totalValueLocked, validatorList.length, requiredValidators);
    }

    function getTokenLiquidity(address token) external view returns (uint256) {
        return tokenLiquidity[token];
    }
}
