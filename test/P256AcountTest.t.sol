// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.28;

// imports - Test, P256Account, PackedUserOperation, EntryPoint

import {Test} from "forge-std/Test.sol";

import {P256Account} from "src/P256Account.sol";

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {IAccountExecute} from "account-abstraction/interfaces/IAccountExecute.sol";

import {Ownable} from "solady/auth/Ownable.sol";

// test contract

// check owner address, entryPoint & public key values - DONE
// onlyOwner functions - DONE
// signature validation and userOp execution
// errors

contract RevertOnEthReceived {
    receive() external payable {
        revert("DO NOT SEND ETH TO THIS CONTRACT");
    }
}

contract P256AccountTest is Test {
    P256Account private s_p256Account;
    EntryPoint private s_entryPoint;
    uint256 private s_privateKey;

    function setUp() public {
        address owner = makeAddr("owner");
        // create entryPoint
        s_entryPoint = new EntryPoint();
        // create privateKey & public key
        s_privateKey = vm.randomUint();
        (uint256 x, uint256 y) = vm.publicKeyP256(s_privateKey);
        P256Account.PublicKey memory publicKey = P256Account.PublicKey(bytes32(x), bytes32(y));

        // deploy it
        s_p256Account = new P256Account(owner, s_entryPoint, publicKey);

        vm.deal(address(s_p256Account), 10 ether);
    }

    function testDeployment() public {
        // create owner
        address owner = makeAddr("owner");
        // create entryPoint
        EntryPoint entryPoint = new EntryPoint();
        // create privateKey & public key
        uint256 privateKey = vm.randomUint();
        (uint256 x, uint256 y) = vm.publicKeyP256(privateKey);
        P256Account.PublicKey memory publicKey = P256Account.PublicKey(bytes32(x), bytes32(y));

        // deploy it
        vm.expectEmit(false, false, false, true);
        emit P256Account.P256Account__PublicKeyChanged(P256Account.PublicKey(bytes32(0), bytes32(0)), publicKey);
        P256Account p256Account = new P256Account(owner, entryPoint, publicKey);

        // get entryPoint, owner, publicKey and assert
        assertEq(address(p256Account.entryPoint()), address(entryPoint));
        assertEq(p256Account.owner(), owner);
        assertEq(keccak256(abi.encode(p256Account.getPublicKey())), keccak256(abi.encode(publicKey)));
    }

    function testChangePublicKey() public {
        // create new publicKey
        uint256 privateKey = 123456;
        (uint256 x, uint256 y) = vm.publicKeyP256(privateKey);
        P256Account.PublicKey memory newPublicKey = P256Account.PublicKey(bytes32(x), bytes32(y));

        // call from unauthorized account
        vm.expectRevert(abi.encodeWithSelector(Ownable.Unauthorized.selector));
        s_p256Account.changePublicKey(newPublicKey);

        // call from owner
        vm.expectEmit(false, false, false, true, address(s_p256Account));
        emit P256Account.P256Account__PublicKeyChanged(s_p256Account.getPublicKey(), newPublicKey);
        vm.prank(s_p256Account.owner());
        s_p256Account.changePublicKey(newPublicKey);
    }

    function testExecuteUserOpFailures() public {
        RevertOnEthReceived failure = new RevertOnEthReceived();

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(s_p256Account),
            nonce: 0,
            initCode: bytes(""),
            callData: bytes(""),
            accountGasLimits: bytes32(uint256(100_000) << 128 | uint256(100_000)),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: bytes(""),
            signature: bytes("")
        });

        bytes32 userOpHash;

        // execute failing test

        userOp.callData = abi.encodeWithSelector(IAccountExecute.executeUserOp.selector, address(failure), 1, bytes(""));
        userOpHash = s_entryPoint.getUserOpHash(userOp);

        vm.expectRevert(
            abi.encodeWithSelector(
                P256Account.P256Account__CallFailed.selector,
                abi.encodeWithSignature("Error(string)", "DO NOT SEND ETH TO THIS CONTRACT")
            )
        );
        vm.prank(address(s_entryPoint));
        s_p256Account.execute(address(failure), 1, bytes(""));

        // execute userOp failing test
        vm.expectRevert(
            abi.encodeWithSelector(
                P256Account.P256Account__CallFailed.selector,
                abi.encodeWithSignature("Error(string)", "DO NOT SEND ETH TO THIS CONTRACT")
            )
        );
        vm.prank(address(s_entryPoint));
        s_p256Account.executeUserOp(userOp, userOpHash);
    }
}
