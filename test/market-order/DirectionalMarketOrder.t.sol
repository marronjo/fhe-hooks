// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

//Foundry Imports
import "forge-std/Test.sol";

//Uniswap Imports
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {TickMath} from "@uniswap/v4-core/src/libraries/TickMath.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {BalanceDelta} from "@uniswap/v4-core/src/types/BalanceDelta.sol";
import {PoolId, PoolIdLibrary} from "@uniswap/v4-core/src/types/PoolId.sol";
import {CurrencyLibrary, Currency} from "@uniswap/v4-core/src/types/Currency.sol";
import {PoolSwapTest} from "@uniswap/v4-core/src/test/PoolSwapTest.sol";
import {StateLibrary} from "@uniswap/v4-core/src/libraries/StateLibrary.sol";
import {Constants} from "@uniswap/v4-core/test/utils/Constants.sol";
import {SortTokens} from "../utils/SortTokens.sol";
import {CustomRevert} from "@uniswap/v4-core/src/libraries/CustomRevert.sol";

import {LiquidityAmounts} from "@uniswap/v4-core/test/utils/LiquidityAmounts.sol";
import {IPositionManager} from "v4-periphery/src/interfaces/IPositionManager.sol";
import {EasyPosm} from "../utils/EasyPosm.sol";
import {Fixtures} from "../utils/Fixtures.sol";

import {MockERC20} from "solmate/src/test/utils/mocks/MockERC20.sol";

import {DirectionalMarketOrder} from "../../src/market-order/DirectionalMarketOrder.sol";

//FHE Imports
import {FHE, InEuint128, euint128} from "@fhenixprotocol/cofhe-contracts/FHE.sol";
import {CoFheTest} from "@fhenixprotocol/cofhe-mock-contracts/CoFheTest.sol";
import {HybridFHERC20} from "../../src/HybridFHERC20.sol";
import {IFHERC20} from "../../src/interface/IFHERC20.sol";

contract DirectionalMarketOrderTest is Test, Fixtures, CoFheTest {
    using EasyPosm for IPositionManager;
    using PoolIdLibrary for PoolKey;
    using CurrencyLibrary for Currency;
    using StateLibrary for IPoolManager;

    DirectionalMarketOrder hook;
    address hookAddr;
    PoolId poolId;

    HybridFHERC20 fheToken0;
    HybridFHERC20 fheToken1;

    Currency fheCurrency0;
    Currency fheCurrency1;

    uint256 tokenId;
    int24 tickLower;
    int24 tickUpper;

    uint128 private constant LIQUIDITY_1E8 = 1e8;
    bool private constant ZERO_FOR_ONE = true;
    bool private constant ONE_FOR_ZERO = false;

    address private user = makeAddr("user");

    function setUp() public {
        //initialise new CoFheTest instance with verbose logging
        //setLog(true);

        bytes memory token0Args = abi.encode("TOKEN0", "TOK0");
        deployCodeTo("HybridFHERC20.sol:HybridFHERC20", token0Args, address(123));

        bytes memory token1Args = abi.encode("TOKEN1", "TOK1");
        deployCodeTo("HybridFHERC20.sol:HybridFHERC20", token1Args, address(456));

        fheToken0 = HybridFHERC20(address(123));
        fheToken1 = HybridFHERC20(address(456));    //ensure address token1 always > address token0

        vm.label(user, "user");
        vm.label(address(this), "test");
        vm.label(address(fheToken0), "token0");
        vm.label(address(fheToken1), "token1");

        // creates the pool manager, utility routers, and test tokens
        deployFreshManagerAndRouters();

        vm.startPrank(user);
        (fheCurrency0, fheCurrency1) = mintAndApprove2Currencies(address(fheToken0), address(fheToken1));

        deployAndApprovePosm(manager);

        // Deploy the hook to an address with the correct flags
        address flags = address(
            uint160(
                Hooks.BEFORE_INITIALIZE_FLAG | Hooks.BEFORE_SWAP_FLAG | Hooks.AFTER_SWAP_FLAG
            ) ^ (0x4444 << 144) // Namespace the hook to avoid collisions
        );
        bytes memory constructorArgs = abi.encode(manager); //Add all the necessary constructor arguments from the hook
        deployCodeTo("DirectionalMarketOrder.sol:DirectionalMarketOrder", constructorArgs, flags);
        hook = DirectionalMarketOrder(flags);

        hookAddr = address(hook);

        vm.label(address(hook), "hook");
        vm.label(address(this), "test");

        // Create the pool
        key = PoolKey(currency0, currency1, 3000, 60, IHooks(hook));
        poolId = key.toId();
        manager.initialize(key, SQRT_PRICE_1_1);

        // Provide full-range liquidity to the pool
        tickLower = TickMath.minUsableTick(key.tickSpacing);
        tickUpper = TickMath.maxUsableTick(key.tickSpacing);

        uint128 liquidityAmount = 100e18;

        (uint256 amount0Expected, uint256 amount1Expected) = LiquidityAmounts.getAmountsForLiquidity(
            SQRT_PRICE_1_1,
            TickMath.getSqrtPriceAtTick(tickLower),
            TickMath.getSqrtPriceAtTick(tickUpper),
            liquidityAmount
        );

        (tokenId,) = posm.mint(
            key,
            tickLower,
            tickUpper,
            liquidityAmount,
            amount0Expected + 1,
            amount1Expected + 1,
            address(this),
            block.timestamp,
            ZERO_BYTES
        );

        InEuint128 memory amount = createInEuint128(0, user);
        fheToken0.mintEncrypted(address(hook), amount);  //init value in mock storage
        fheToken1.mintEncrypted(address(hook), amount);  //init value in mock storage

        vm.stopPrank();
    }

    function test_InitializeFailed() public {
        address flags = address(
            uint160(
                Hooks.BEFORE_INITIALIZE_FLAG | Hooks.BEFORE_SWAP_FLAG | Hooks.AFTER_SWAP_FLAG
            ) ^ (0x4444 << 144) // Namespace the hook to avoid collisions
        );
        bytes memory constructorArgs = abi.encode(manager); //Add all the necessary constructor arguments from the hook
        deployCodeTo("DirectionalMarketOrder.sol:DirectionalMarketOrder", constructorArgs, flags);
        DirectionalMarketOrder badHook = DirectionalMarketOrder(flags);

        //
        // mock erc20 tokens do not have isFherc20 method, 
        // therefore invalid for hook initialisation
        //
        MockERC20 badToken0 = new MockERC20("Test0", "T0", 1);
        MockERC20 badToken1 = new MockERC20("Test1", "T1", 1);

        (Currency c0, Currency c1) = address(badToken0) > address(badToken1) ?
        (Currency.wrap(address(badToken1)), Currency.wrap(address(badToken0))) :
        (Currency.wrap(address(badToken0)), Currency.wrap(address(badToken1)));

        // Create the pool
        PoolKey memory badKey = PoolKey(c0, c1, 3000, 60, IHooks(badHook));
        poolId = badKey.toId();

        vm.expectRevert();
        manager.initialize(badKey, SQRT_PRICE_1_1);
    }

    function test_placeMarketOrderCorrectBalanceTransfersZeroForOne() public {
        (
            euint128 userBefore0,
            euint128 hookBefore0,
            euint128 userBefore1,
            euint128 hookBefore1
        ) = _getAllBalances();

        vm.startPrank(user);
        InEuint128 memory liquidity = createInEuint128(LIQUIDITY_1E8, user);
        hook.placeMarketOrder(key, ZERO_FOR_ONE, liquidity);
        vm.stopPrank();

        _assertTokenBalanceChange(fheToken0, user, hookAddr, LIQUIDITY_1E8, userBefore0, hookBefore0);
        _assertTokenBalanceEqual(fheToken1, user, hookAddr, userBefore1, hookBefore1);
    }

    function test_placeMarketOrderCorrectBalanceTransfersOneForZero() public {
        (
            euint128 userBefore0,
            euint128 hookBefore0,
            euint128 userBefore1,
            euint128 hookBefore1
        ) = _getAllBalances();

        vm.startPrank(user);
        InEuint128 memory liquidity = createInEuint128(LIQUIDITY_1E8, user);
        hook.placeMarketOrder(key, ONE_FOR_ZERO, liquidity);
        vm.stopPrank();

        _assertTokenBalanceChange(fheToken1, user, hookAddr, LIQUIDITY_1E8, userBefore0, hookBefore0);
        _assertTokenBalanceEqual(fheToken0, user, hookAddr, userBefore1, hookBefore1);
    }

    function test_placeMarketOrderCorrectStorageOneForZero() public {
        vm.startPrank(user);
        InEuint128 memory liquidity = createInEuint128(LIQUIDITY_1E8, user);
        hook.placeMarketOrder(key, ONE_FOR_ZERO, liquidity);
        vm.stopPrank();

        (uint8 orderCount, euint128 totalLiquidity) = hook.getCurrentEpoch(ONE_FOR_ZERO);

        vm.prank(user);
        euint128 userLiquidity = hook.getLiquidityCurrentEpoch(ONE_FOR_ZERO);

        assertEq(orderCount, 1);
        assertHashValue(totalLiquidity, LIQUIDITY_1E8);
        assertHashValue(userLiquidity, LIQUIDITY_1E8);
    }

    function test_placeMarketOrderCorrectStorageZeroForOne() public {
        vm.startPrank(user);
        InEuint128 memory liquidity = createInEuint128(LIQUIDITY_1E8, user);
        hook.placeMarketOrder(key, ZERO_FOR_ONE, liquidity);
        vm.stopPrank();

        (uint8 orderCount, euint128 totalLiquidity) = hook.getCurrentEpoch(ZERO_FOR_ONE);

        vm.prank(user);
        euint128 userLiquidity = hook.getLiquidityCurrentEpoch(ZERO_FOR_ONE);

        assertEq(orderCount, 1);
        assertHashValue(totalLiquidity, LIQUIDITY_1E8);
        assertHashValue(userLiquidity, LIQUIDITY_1E8);
    }

    // ----------------------------------
    //
    //      ... Helper Functions ...
    //
    // ----------------------------------

    function _getAllBalances() private view returns(euint128, euint128, euint128, euint128) {
        return(
            fheToken0.encBalances(user),
            fheToken0.encBalances(hookAddr),
            fheToken1.encBalances(user),
            fheToken1.encBalances(hookAddr)
        );
    }

    function _assertTokenBalanceChange(HybridFHERC20 token, address from, address to, uint128 amount, euint128 beforeFromBalance, euint128 beforeToBalance) private view {
        euint128 fromBalanceAfter = token.encBalances(from);
        euint128 toBalanceAfter = token.encBalances(to);

        assertHashValue(fromBalanceAfter, _mockStorageHelper(beforeFromBalance) - amount);
        assertHashValue(toBalanceAfter, _mockStorageHelper(beforeToBalance) + amount);        
    }

    function _assertTokenBalanceEqual(HybridFHERC20 token, address from, address to, euint128 beforeFromBalance, euint128 beforeToBalance) private view {
        euint128 fromBalanceAfter = token.encBalances(from);
        euint128 toBalanceAfter = token.encBalances(to);

        assertHashValue(fromBalanceAfter, _mockStorageHelper(beforeFromBalance));
        assertHashValue(toBalanceAfter, _mockStorageHelper(beforeToBalance));
    }

    // help with easier to read test assertions
    function _mockStorageHelper(euint128 value) private view returns(uint128){
        uint256 ctHash = euint128.unwrap(value);
        if(!inMockStorage(ctHash)){
            return 0;
        }
        return uint128(mockStorage(ctHash));
    }

    function mintAndApprove2Currencies(address tokenA, address tokenB) internal returns (Currency, Currency) {
        Currency _currencyA = mintAndApproveCurrency(tokenA);
        Currency _currencyB = mintAndApproveCurrency(tokenB);

        (currency0, currency1) =
            SortTokens.sort(Currency.unwrap(_currencyA),Currency.unwrap(_currencyB));
        return (currency0, currency1);
    }

    function mintAndApproveCurrency(address token) internal returns (Currency currency) {
        IFHERC20(token).mint(user, 2 ** 250);
        IFHERC20(token).mint(address(this), 2 ** 250);

        //InEuint128 memory amount = createInEuint128(2 ** 120, address(this));
        InEuint128 memory amountUser = createInEuint128(2 ** 120, user);

        //IFHERC20(token).mintEncrypted(address(this), amount);
        IFHERC20(token).mintEncrypted(user, amountUser);

        address[9] memory toApprove = [
            address(swapRouter),
            address(swapRouterNoChecks),
            address(modifyLiquidityRouter),
            address(modifyLiquidityNoChecks),
            address(donateRouter),
            address(takeRouter),
            address(claimsRouter),
            address(nestedActionRouter.executor()),
            address(actionsRouter)
        ];

        for (uint256 i = 0; i < toApprove.length; i++) {
            IFHERC20(token).approve(toApprove[i], Constants.MAX_UINT256);
        }

        return Currency.wrap(token);
    }
}
