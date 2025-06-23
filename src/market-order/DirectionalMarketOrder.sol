// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

//Uniswap Imports
import {BaseHook} from "v4-periphery/src/utils/BaseHook.sol";

import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {SwapParams, ModifyLiquidityParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";
import {Currency, CurrencyLibrary} from "@uniswap/v4-core/src/types/Currency.sol";
import {CurrencySettler} from "@uniswap/v4-core/test/utils/CurrencySettler.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "@uniswap/v4-core/src/types/PoolId.sol";
import {EpochLibrary, Epoch} from "../lib/EpochLibrary.sol";
import {StateLibrary} from "@uniswap/v4-core/src/libraries/StateLibrary.sol";
import {BalanceDelta} from "@uniswap/v4-core/src/types/BalanceDelta.sol";
import {BeforeSwapDelta, BeforeSwapDeltaLibrary} from "@uniswap/v4-core/src/types/BeforeSwapDelta.sol";
import {TickMath} from "@uniswap/v4-core/src/libraries/TickMath.sol";
import {Queue} from "../Queue.sol";

//FHE Imports
import {FHE, InEuint128, euint128, InEbool, ebool, euint8} from "@fhenixprotocol/cofhe-contracts/FHE.sol";
import {IFHERC20} from "../interface/IFHERC20.sol";

contract MarketOrder is BaseHook {

    error MarketOrder__InvalidFHERC20Token(address token);

    using PoolIdLibrary for PoolKey;
    using EpochLibrary for Epoch;
    using CurrencyLibrary for Currency;
    using CurrencySettler for Currency;
    using StateLibrary for IPoolManager;

    // NOTE: ---------------------------------------------------------
    // more natural syntax with euint operations by using FHE library
    // all euint types are wrapped forms of uint256
    // therefore using library for uint256 works for all euint types
    // ---------------------------------------------------------------
    using FHE for uint256;

    struct EpochInfo {
        uint8 orderCount;
        euint128 totalLiquidity;
        mapping(address => euint128) liquidity;
    }

    struct QueueInfo {
        Queue zeroForOne;
        Queue oneForZero;
    }

    bytes internal constant ZERO_BYTES = bytes("");

    Epoch private zeroForOneEpoch = Epoch.wrap(1);
    Epoch private oneForZeroEpoch = Epoch.wrap(1);

    //TODO make mappings pool agnostic + rename
    mapping(Epoch => EpochInfo) zeroForOneEpochs;
    mapping(Epoch => EpochInfo) oneForZeroEpochs;

    // each pool has 2 separate decryption queues
    // one for each trade direction
    mapping(PoolId key => QueueInfo queues) public poolQueue;

    euint128 immutable ZERO_128;
    euint8 immutable ONE_8;
    uint8 immutable ORDER_THRESHOLD = 5;

    constructor(IPoolManager _poolManager) BaseHook(_poolManager) {
        ZERO_128 = FHE.asEuint128(0);
        ONE_8 = FHE.asEuint8(1);

        FHE.allowThis(ZERO_128);
        FHE.allowThis(ONE_8);
    }

    function getHookPermissions() public pure override returns (Hooks.Permissions memory) {
        return Hooks.Permissions({
            beforeInitialize: true,
            afterInitialize: false,
            beforeAddLiquidity: false,
            afterAddLiquidity: false,
            beforeRemoveLiquidity: false,
            afterRemoveLiquidity: false,
            beforeSwap: true,
            afterSwap: true,
            beforeDonate: false,
            afterDonate: false,
            beforeSwapReturnDelta: false,
            afterSwapReturnDelta: false,
            afterAddLiquidityReturnDelta: false,
            afterRemoveLiquidityReturnDelta: false
        });
    }

    //if queue does not exist for given pool and direction, deploy new queue
    function getPoolQueue(PoolKey calldata key, bool zeroForOne) private returns(Queue queue){
        QueueInfo storage queueInfo = poolQueue[key.toId()];

        if(zeroForOne){
            if(address(queueInfo.zeroForOne) == address(0)){
                queueInfo.zeroForOne = new Queue();
            }
            queue = queueInfo.zeroForOne;
        } else {
            if(address(queueInfo.oneForZero) == address(0)){
                queueInfo.oneForZero = new Queue();
            }
            queue = queueInfo.oneForZero;
        }
    }

    // -----------------------------------------------
    // NOTE: see IHooks.sol for function documentation
    // -----------------------------------------------

    function _beforeInitialize(address, PoolKey calldata key, uint160)
        pure
        internal
        override
        returns(bytes4)
    {
        verifyFHERC20Token(Currency.unwrap(key.currency0));
        verifyFHERC20Token(Currency.unwrap(key.currency1));
        return (BaseHook.beforeInitialize.selector);
    }

    function verifyFHERC20Token(address token) private pure {
        try IFHERC20(token).isFherc20() returns(bool isFherc20) {
            if(!isFherc20){
                revert MarketOrder__InvalidFHERC20Token(token);
            }
        } catch {
            revert MarketOrder__InvalidFHERC20Token(token);
        }
    }

    function placeMarketOrder(PoolKey calldata key, bool zeroForOne, InEuint128 calldata liquidity) external {
        ebool _zeroForOne = FHE.asEbool(zeroForOne);
        euint128 _liquidity = FHE.asEuint128(liquidity);

        euint128 totalLiquidity;


        if(zeroForOne){
            zeroForOneEpochs[zeroForOneEpoch].orderCount++;

            euint128 zeroForOneUser = zeroForOneEpochs[zeroForOneEpoch].liquidity[msg.sender];
            zeroForOneEpochs[zeroForOneEpoch].liquidity[msg.sender] = FHE.select(_zeroForOne, FHE.add(zeroForOneUser, _liquidity), zeroForOneUser);
            
            FHE.allowThis(zeroForOneEpochs[zeroForOneEpoch].liquidity[msg.sender]);
            FHE.allow(zeroForOneEpochs[zeroForOneEpoch].liquidity[msg.sender], msg.sender);

            euint128 zeroForOneLiquidity = zeroForOneEpochs[zeroForOneEpoch].totalLiquidity;

            zeroForOneEpochs[zeroForOneEpoch].totalLiquidity = FHE.add(zeroForOneLiquidity, _liquidity);
            FHE.allowThis(zeroForOneEpochs[zeroForOneEpoch].totalLiquidity);

            FHE.allow(_liquidity, Currency.unwrap(key.currency0));
            IFHERC20(Currency.unwrap(key.currency0)).transferFromEncrypted(msg.sender, address(this), _liquidity);
        } else {
            oneForZeroEpochs[oneForZeroEpoch].orderCount++;

            euint128 oneForZeroUser = oneForZeroEpochs[oneForZeroEpoch].liquidity[msg.sender];
            oneForZeroEpochs[oneForZeroEpoch].liquidity[msg.sender] = FHE.select(_zeroForOne, oneForZeroUser, FHE.add(oneForZeroUser, _liquidity)); 

            FHE.allowThis(oneForZeroEpochs[oneForZeroEpoch].liquidity[msg.sender]);
            FHE.allow(oneForZeroEpochs[oneForZeroEpoch].liquidity[msg.sender], msg.sender);

            euint128 oneForZeroLiquidity = oneForZeroEpochs[oneForZeroEpoch].totalLiquidity;

            oneForZeroEpochs[oneForZeroEpoch].totalLiquidity = FHE.add(oneForZeroLiquidity, _liquidity);
            FHE.allowThis(oneForZeroEpochs[oneForZeroEpoch].totalLiquidity);

            FHE.allow(_liquidity, Currency.unwrap(key.currency1));
            IFHERC20(Currency.unwrap(key.currency1)).transferFromEncrypted(msg.sender, address(this), _liquidity);
        }
    }

    function _beforeSwap(address, PoolKey calldata key, SwapParams calldata, bytes calldata)
        internal
        override
        returns (bytes4, BeforeSwapDelta, uint24)
    {
        // check if any decrypted orders ready to execute
        (uint128 liquidityZ, bool executeZeroForOne) = _checkDecryptedOrders(key, true);
        (uint128 liquidityO, bool executeOneForZero) = _checkDecryptedOrders(key, false);

        if(executeZeroForOne){
            _executeDecryptedOrders(key, liquidityZ, true);
        }
        if(executeOneForZero){
            _executeDecryptedOrders(key, liquidityO, false);
        }

        return (BaseHook.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
    }

    function _afterSwap(address, PoolKey calldata key, SwapParams calldata, BalanceDelta, bytes calldata)
        internal
        override
        returns (bytes4, int128)
    {
        // check if order threshold is met
        if(zeroForOneEpochs[zeroForOneEpoch].orderCount >= ORDER_THRESHOLD){
            _decryptBundledOrders(key, true, zeroForOneEpochs[zeroForOneEpoch].totalLiquidity);
        }
        if(oneForZeroEpochs[oneForZeroEpoch].orderCount >= ORDER_THRESHOLD){
            _decryptBundledOrders(key, false, oneForZeroEpochs[oneForZeroEpoch].totalLiquidity);
        }

        return (BaseHook.afterSwap.selector, 0);
    }

    function _checkDecryptedOrders(PoolKey calldata key, bool zeroForOne) private returns(uint128 liquidity, bool decrypted){
        Queue queue = getPoolQueue(key, zeroForOne);
        if(!queue.isEmpty()){
            euint128 handle = queue.peek();
            (liquidity, decrypted) = FHE.getDecryptResultSafe(handle);
            if(decrypted){
                queue.pop();
            }
        }
    }

    function _executeDecryptedOrders(PoolKey calldata key, uint128 decryptedLiquidity, bool zeroForOne) private {
        BalanceDelta delta = _swapPoolManager(key, zeroForOne, -int256(uint256(decryptedLiquidity))); 
        (uint128 amount0, uint128 amount1) = _settlePoolManagerBalances(key, delta, zeroForOne);
        //store outputs
    }

    function _settlePoolManagerBalances(PoolKey calldata key, BalanceDelta delta, bool zeroForOne) private returns(uint128 amount0, uint128 amount1) {
        if(zeroForOne){
            amount0 = uint128(-delta.amount0()); // hook sends in -amount0 and receives +amount1
            amount1 = uint128(delta.amount1());
        } else {
            amount0 = uint128(delta.amount0()); // hook sends in -amount1 and receives +amount0
            amount1 = uint128(-delta.amount1());
        }

        // settle with pool manager the unencrypted FHERC20 tokens
        // send in tokens owed to pool and take tokens owed to the hook
        if (delta.amount0() < 0) {
            key.currency0.settle(poolManager, address(this), uint256(amount0), false);
            key.currency1.take(poolManager, address(this), uint256(amount1), false);

            IFHERC20(Currency.unwrap(key.currency1)).wrap(address(this), amount1); //encrypted wrap newly received (taken) token1
        } else {
            key.currency1.settle(poolManager, address(this), uint256(amount1), false);
            key.currency0.take(poolManager, address(this), uint256(amount0), false);

            IFHERC20(Currency.unwrap(key.currency0)).wrap(address(this), amount0); //encrypted wrap newly received (taken) token0
        }
    }

    function _swapPoolManager(PoolKey calldata key, bool zeroForOne, int256 amountSpecified) private returns(BalanceDelta delta) {
        SwapParams memory params = SwapParams({
            zeroForOne: zeroForOne,
            amountSpecified: amountSpecified,
            sqrtPriceLimitX96: zeroForOne ? 
                        TickMath.MIN_SQRT_PRICE + 1 :   // increasing price of token 1, lower ratio
                        TickMath.MAX_SQRT_PRICE - 1
        });

        delta = poolManager.swap(key, params, ZERO_BYTES);
    }

    function _noOp() private view returns(euint128){
        return ZERO_128;
    }

    function _decryptBundledOrders(PoolKey calldata key, bool zeroForOne, euint128 handle) private returns(euint128){
        FHE.decrypt(handle);

        //add handle to decryption queue
        //increment epoch
        if(zeroForOne){
            getPoolQueue(key, zeroForOne).push(handle);
            zeroForOneEpoch.unsafeIncrement();
        } else {
            getPoolQueue(key, zeroForOne).push(handle);
            oneForZeroEpoch.unsafeIncrement();
        }

        return ZERO_128;
    }
}
