// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

//Foundry Imports
import "forge-std/Test.sol";
import {HybridFHERC20} from "../src/HybridFHERC20.sol";
import {CoFheTest} from "@fhenixprotocol/cofhe-mock-contracts/CoFheTest.sol";
import {FHE, euint128, InEuint128} from "@fhenixprotocol/cofhe-contracts/FHE.sol";


contract HybridFHERC20Test is Test, CoFheTest {

    HybridFHERC20 private token;

    address private user = makeAddr("user");
    address private user2 = makeAddr("user2");
    address private zero = address(0x0);

    uint128 userStartingBalance = 1e10;
    uint128 user2StartingBalance = 0;

    function setUp() public {
        // setLog(true); // set verbose logging for cofhetest

        token = new HybridFHERC20("TEST", "TST");

        vm.label(user, "user");
        vm.label(address(token), "token");

        vm.startPrank(user);
        token.mint(user, userStartingBalance);
        
        InEuint128 memory balance = createInEuint128(uint128(userStartingBalance), user);
        token.mintEncrypted(user, balance);
        vm.stopPrank();

        token.mintEncrypted(user2, FHE.asEuint128(0));  //init value in mock storage
    }

    function testPublicMint() public {
        assertEq(token.balanceOf(user), userStartingBalance);

        vm.prank(user);
        token.mint(user, 1e5);

        assertEq(token.balanceOf(user), userStartingBalance + 1e5);
    }

    function testPublicBurn() public {
        assertEq(token.balanceOf(user), userStartingBalance);

        vm.prank(user);
        token.burn(user, 1e5);

        assertEq(token.balanceOf(user), userStartingBalance - 1e5);
    }

    function testEncryptedMintInEuint() public {
        assertHashValue(token.encBalances(user), userStartingBalance);
        assertHashValue(token.totalEncryptedSupply(), userStartingBalance);

        vm.startPrank(user);
        InEuint128 memory balance = createInEuint128(1e5, user);
        token.mintEncrypted(user, balance);
        vm.stopPrank();

        assertHashValue(token.encBalances(user), userStartingBalance + 1e5);
        //one holder, therefore user balance same as total encrypted supply
        assertHashValue(token.totalEncryptedSupply(), userStartingBalance + 1e5);
    }

    function testEncryptedMintEuint() public {
        assertHashValue(token.encBalances(user), userStartingBalance);
        assertHashValue(token.totalEncryptedSupply(), userStartingBalance);

        vm.startPrank(user);
        euint128 balance = FHE.asEuint128(1e5);

        //since InEuint with user signature is not created, must allow token to use new balance
        FHE.allow(balance, address(token)); 
        token.mintEncrypted(user, balance);
        vm.stopPrank();

        assertHashValue(token.encBalances(user), userStartingBalance + 1e5);
        assertHashValue(token.totalEncryptedSupply(), userStartingBalance + 1e5);
    }

    function testEncryptedBurnInEuint() public {
        assertHashValue(token.encBalances(user), userStartingBalance);
        assertHashValue(token.totalEncryptedSupply(), userStartingBalance);

        vm.startPrank(user);
        InEuint128 memory balance = createInEuint128(1e5, user);
        token.burnEncrypted(user, balance);
        vm.stopPrank();

        assertHashValue(token.encBalances(user), userStartingBalance - 1e5);
        assertHashValue(token.totalEncryptedSupply(), userStartingBalance - 1e5);
    }

    function testEncryptedBurnEuint() public {
        assertHashValue(token.encBalances(user), userStartingBalance);
        assertHashValue(token.totalEncryptedSupply(), userStartingBalance);

        vm.startPrank(user);
        euint128 balance = FHE.asEuint128(1e5);

        //since InEuint with user signature is not created, must allow token to use new balance
        FHE.allow(balance, address(token)); 
        token.burnEncrypted(user, balance);
        vm.stopPrank();

        assertHashValue(token.encBalances(user), userStartingBalance - 1e5);
        assertHashValue(token.totalEncryptedSupply(), userStartingBalance - 1e5);
    }

    function testTransferEncryptedInEuint() public {
        assertHashValue(token.encBalances(user), userStartingBalance);
        assertHashValue(token.encBalances(user2), user2StartingBalance);
        assertHashValue(token.totalEncryptedSupply(), userStartingBalance);

        vm.startPrank(user);
        InEuint128 memory amount = createInEuint128(1e5, user);
        euint128 amountToSend = token.transferEncrypted(user2, amount);
        vm.stopPrank();

        assertHashValue(amountToSend, 1e5);

        assertHashValue(token.encBalances(user), userStartingBalance - 1e5);
        assertHashValue(token.encBalances(user2), user2StartingBalance + 1e5);
        assertHashValue(token.totalEncryptedSupply(), userStartingBalance);     //total supply stay the same
    }

    function testTransferEncryptedEuint() public {
        assertHashValue(token.encBalances(user), userStartingBalance);
        assertHashValue(token.encBalances(user2), user2StartingBalance);
        assertHashValue(token.totalEncryptedSupply(), userStartingBalance);

        vm.startPrank(user);
        euint128 amount = FHE.asEuint128(1e5);

        FHE.allow(amount, address(token)); 
        token.transferEncrypted(user2, amount);
        vm.stopPrank();

        assertHashValue(token.encBalances(user), userStartingBalance - 1e5);
        assertHashValue(token.encBalances(user2), user2StartingBalance + 1e5);
        assertHashValue(token.totalEncryptedSupply(), userStartingBalance);
    }

    function testTransferEncryptedInsufficientBalance() public {
        assertHashValue(token.encBalances(user), userStartingBalance);
        assertHashValue(token.encBalances(user2), user2StartingBalance);
        assertHashValue(token.totalEncryptedSupply(), userStartingBalance);

        vm.startPrank(user);
        InEuint128 memory amount = createInEuint128(1e11, user);
        euint128 amountToSend = token.transferEncrypted(user2, amount);
        vm.stopPrank();

        assertHashValue(amountToSend, 0);

        //ensure balances stay the same since 1e11 > user balance (1e10)
        assertHashValue(token.encBalances(user), userStartingBalance);
        assertHashValue(token.encBalances(user2), user2StartingBalance);
        assertHashValue(token.totalEncryptedSupply(), userStartingBalance);     //total supply stay the same
    }

    function testTransferFromEncryptedInEuint() public {
        assertHashValue(token.encBalances(user), userStartingBalance);
        assertHashValue(token.encBalances(user2), user2StartingBalance);
        assertHashValue(token.totalEncryptedSupply(), userStartingBalance);

        vm.startPrank(user);
        InEuint128 memory amount = createInEuint128(1e5, user);
        token.transferFromEncrypted(user, user2, amount);
        vm.stopPrank();

        assertHashValue(token.encBalances(user), userStartingBalance - 1e5);
        assertHashValue(token.encBalances(user2), user2StartingBalance + 1e5);
        assertHashValue(token.totalEncryptedSupply(), userStartingBalance);
    }

    function testTransferFromEncryptedEuint() public {
        assertHashValue(token.encBalances(user), userStartingBalance);
        assertHashValue(token.encBalances(user2), user2StartingBalance);
        assertHashValue(token.totalEncryptedSupply(), userStartingBalance);

        vm.startPrank(user);
        euint128 amount = FHE.asEuint128(1e5);

        FHE.allow(amount, address(token)); 
        token.transferFromEncrypted(user, user2, amount);
        vm.stopPrank();

        assertHashValue(token.encBalances(user), userStartingBalance - 1e5);
        assertHashValue(token.encBalances(user2), user2StartingBalance + 1e5);
        assertHashValue(token.totalEncryptedSupply(), userStartingBalance);
    }

    function testTransferInvalidSender() public {
        assertHashValue(token.encBalances(user), userStartingBalance);
        assertHashValue(token.encBalances(user2), user2StartingBalance);
        assertHashValue(token.totalEncryptedSupply(), userStartingBalance);

        euint128 amount = FHE.asEuint128(1e5);
        FHE.allow(amount, address(token)); 

        vm.expectRevert(HybridFHERC20.HybridFHERC20__InvalidSender.selector);

        token.transferFromEncrypted(zero, user2, amount);
    }

    function testTransferInvalidReceiver() public {
        assertHashValue(token.encBalances(user), userStartingBalance);
        assertHashValue(token.encBalances(user2), user2StartingBalance);
        assertHashValue(token.totalEncryptedSupply(), userStartingBalance);

        euint128 amount = FHE.asEuint128(1e5);
        FHE.allow(amount, address(token)); 

        vm.expectRevert(HybridFHERC20.HybridFHERC20__InvalidReceiver.selector);

        token.transferFromEncrypted(user, zero, amount);
    }

    function testDecryptBalance() public {
        assertHashValue(token.encBalances(user), userStartingBalance);
        token.decryptBalance(user);

        uint8 count = 0;
        bool success = false;
        while (!success && count < 11) {
            try token.getDecryptBalanceResult(user) returns (uint128 balance) {
                success = true;
                assertHashValue(token.encBalances(user), balance);
            } catch {
                vm.warp(block.timestamp + 1);
                count += 1;
            }
        }
    }

    function testDecryptBalanceSafe() public {
        assertHashValue(token.encBalances(user), userStartingBalance);
        token.decryptBalance(user);

        uint8 count = 0;
        bool success = false;
        while (!success && count < 11) {
            (uint256 result, bool decrypted) = token.getDecryptBalanceResultSafe(user);
            if (decrypted) {
                assertEq(result, userStartingBalance);
                success = true;
            } else {
                vm.warp(block.timestamp + 1);
                count += 1;
            }
        }
    }

    function testWrap() public {
        assertHashValue(token.encBalances(user), userStartingBalance);
        assertHashValue(token.encBalances(user2), user2StartingBalance);
        assertHashValue(token.totalEncryptedSupply(), userStartingBalance);

        token.wrap(user, 1e5);

        assertHashValue(token.encBalances(user), userStartingBalance + 1e5);
        assertHashValue(token.totalEncryptedSupply(), userStartingBalance + 1e5);

        assertEq(token.balanceOf(user), userStartingBalance - 1e5);
        assertEq(token.totalSupply(), userStartingBalance - 1e5); //burn 1e5 public totalSupply
    }

    function testRequestUnwrapInEuint() public {
        vm.startPrank(user);
        InEuint128 memory amount = createInEuint128(1e5, user);
        euint128 handle = token.requestUnwrap(user, amount);

        vm.warp(block.timestamp + 11);  //ensure result is decrypted
        uint128 unwrappedAmount = token.getUnwrapResult(user, handle);

        assertEq(unwrappedAmount, 1e5);

        assertHashValue(token.encBalances(user), userStartingBalance - unwrappedAmount);
        assertHashValue(token.totalEncryptedSupply(), userStartingBalance - unwrappedAmount);

        assertEq(token.balanceOf(user), userStartingBalance + unwrappedAmount);
        assertEq(token.totalSupply(), userStartingBalance + unwrappedAmount);
    }

    function testRequestUnwrap() public {
        euint128 amount = FHE.asEuint128(1e5);
        FHE.allow(amount, address(token));
        euint128 handle = token.requestUnwrap(user, amount);

        vm.warp(block.timestamp + 11);  //ensure result is decrypted
        uint128 unwrappedAmount = token.getUnwrapResult(user, handle);

        assertEq(unwrappedAmount, 1e5);

        assertHashValue(token.encBalances(user), userStartingBalance - unwrappedAmount);
        assertHashValue(token.totalEncryptedSupply(), userStartingBalance - unwrappedAmount);

        assertEq(token.balanceOf(user), userStartingBalance + unwrappedAmount);
        assertEq(token.totalSupply(), userStartingBalance + unwrappedAmount);
    }

    function testRequestUnwrapSafe() public {
        euint128 amount = FHE.asEuint128(1e5);
        FHE.allow(amount, address(token));
        euint128 handle = token.requestUnwrap(user, amount);

        vm.warp(block.timestamp + 11);  //ensure result is decrypted
        (uint128 unwrappedAmount, bool decrypted) = token.getUnwrapResultSafe(user, handle);

        assertTrue(decrypted);
        assertEq(unwrappedAmount, 1e5);

        assertHashValue(token.encBalances(user), userStartingBalance - unwrappedAmount);
        assertHashValue(token.totalEncryptedSupply(), userStartingBalance - unwrappedAmount);

        assertEq(token.balanceOf(user), userStartingBalance + unwrappedAmount);
        assertEq(token.totalSupply(), userStartingBalance + unwrappedAmount);
    }
}