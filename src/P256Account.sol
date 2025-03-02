// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.28;

import {BaseAccount} from "account-abstraction/core/BaseAccount.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {IAccountExecute} from "account-abstraction/interfaces/IAccountExecute.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {_packValidationData} from "account-abstraction/core/Helpers.sol";

import {P256} from "solady/utils/P256.sol";
import {Ownable} from "solady/auth/Ownable.sol";

contract P256Account is BaseAccount, Ownable, IAccountExecute {
    // events - setPubKey
    event P256Account__PublicKeyChanged(PublicKey oldPublicKey, PublicKey newPublicKey);

    // errors - callFailed
    error P256Account__CallFailed(bytes err);

    // pubkey
    struct PublicKey {
        bytes32 x;
        bytes32 y;
    }

    // entryPoint
    IEntryPoint private s_entryPoint;
    // s_pubKey
    PublicKey private s_publicKey;

    constructor(address _owner, IEntryPoint _entryPoint, PublicKey memory _publicKey) {
        _initializeOwner(_owner);

        s_entryPoint = _entryPoint;
        _setPublicKey(_publicKey);
    }

    // changePublicKey
    function changePublicKey(PublicKey memory newPublicKey) external onlyOwner {
        _setPublicKey(newPublicKey);
    }

    // execute
    function execute(address destination, uint256 value, bytes calldata data) external {
        _requireFromEntryPoint();
        (bool success, bytes memory err) = destination.call{value: value}(data);
        require(success, P256Account__CallFailed(err));
    }

    // executeUserOp
    function executeUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external {
        (userOpHash);
        _requireFromEntryPoint();

        (address destination, uint256 value, bytes memory data) = abi.decode(userOp.callData[4:], (address, uint256, bytes));
        (bool success, bytes memory err) = destination.call{value: value}(data);
        require(success, P256Account__CallFailed(err));
    }

    // getPublicKey
    function getPublicKey() external view returns (PublicKey memory) {
        return s_publicKey;
    }

    function entryPoint() public view override returns (IEntryPoint) {
        return s_entryPoint;
    }

    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        view
        override
        returns (uint256 validationData)
    {
        // decode the signature
        (bytes32 r, bytes32 s) = abi.decode(userOp.signature, (bytes32, bytes32));

        // verify the signature
        bool isVerified = P256.verifySignature(userOpHash, s_publicKey.x, s_publicKey.y, r, s);

        // return correct validationData
        return _packValidationData(isVerified, uint48(block.timestamp + 20 minutes), 0);
    }

    function _guardInitializeOwner() internal pure override returns (bool guard) {
        return true;
    }

    // _setPublicKey
    function _setPublicKey(PublicKey memory newPublicKey) internal {
        emit P256Account__PublicKeyChanged(s_publicKey, newPublicKey);
        s_publicKey = newPublicKey;
    }
}
