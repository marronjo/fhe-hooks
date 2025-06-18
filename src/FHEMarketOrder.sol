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
import {EpochLibrary, Epoch} from "./lib/EpochLibrary.sol";
import {StateLibrary} from "@uniswap/v4-core/src/libraries/StateLibrary.sol";
import {BalanceDelta} from "@uniswap/v4-core/src/types/BalanceDelta.sol";
import {BeforeSwapDelta, BeforeSwapDeltaLibrary} from "@uniswap/v4-core/src/types/BeforeSwapDelta.sol";

//FHE Imports
import {FHE, InEuint128, euint128, InEbool, ebool} from "@fhenixprotocol/cofhe-contracts/FHE.sol";
import {IFHERC20} from "./interface/IFHERC20.sol";

contract FHEMarketOrder is BaseHook {

    error FHEMarketOrder__InvalidFHERC20Token(address token);

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
        euint128 totalLiquidity;
        mapping(address => euint128) liquidity;
    }

    Epoch private zeroForOneEpoch = Epoch.wrap(1);
    Epoch private oneForZeroEpoch = Epoch.wrap(1);

    mapping(Epoch => EpochInfo) zeroForOneEpochs;
    mapping(Epoch => EpochInfo) oneForZeroEpochs;

    euint128 immutable ZERO;

    constructor(IPoolManager _poolManager) BaseHook(_poolManager) {
        ZERO = FHE.asEuint128(0);
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
                revert FHEMarketOrder__InvalidFHERC20Token(token);
            }
        } catch {
            revert FHEMarketOrder__InvalidFHERC20Token(token);
        }
    }

    function placeMarketOrder(PoolKey calldata key, InEbool calldata zeroForOne, InEuint128 calldata liquidity) external {
        ebool _zeroForOne = FHE.asEbool(zeroForOne);
        euint128 _liquidity = FHE.asEuint128(liquidity);

        euint128 zeroForOneLiquidity = zeroForOneEpochs[zeroForOneEpoch].totalLiquidity;
        euint128 oneForZeroLiquidity = oneForZeroEpochs[oneForZeroEpoch].totalLiquidity;

        euint128 zeroForOneUser = zeroForOneEpochs[zeroForOneEpoch].liquidity[msg.sender];
        euint128 oneForZeroUser = oneForZeroEpochs[oneForZeroEpoch].liquidity[msg.sender];

        // ----- Store Market Orders -----
    
        // - user liquidity
        zeroForOneEpochs[zeroForOneEpoch].liquidity[msg.sender] = FHE.select(_zeroForOne, FHE.add(zeroForOneUser, _liquidity), zeroForOneUser);
        oneForZeroEpochs[oneForZeroEpoch].liquidity[msg.sender] = FHE.select(_zeroForOne, oneForZeroUser, FHE.add(oneForZeroUser, _liquidity)); 

        // - add contract allowances
        FHE.allowThis(zeroForOneEpochs[zeroForOneEpoch].liquidity[msg.sender]);
        FHE.allowThis(oneForZeroEpochs[oneForZeroEpoch].liquidity[msg.sender]);
        
        // - add user allowances
        FHE.allow(zeroForOneEpochs[zeroForOneEpoch].liquidity[msg.sender], msg.sender);
        FHE.allow(oneForZeroEpochs[oneForZeroEpoch].liquidity[msg.sender], msg.sender);
        
        // - total liquidity
        zeroForOneEpochs[zeroForOneEpoch].totalLiquidity = FHE.select(_zeroForOne, FHE.add(zeroForOneLiquidity, _liquidity), zeroForOneLiquidity);
        oneForZeroEpochs[oneForZeroEpoch].totalLiquidity = FHE.select(_zeroForOne, oneForZeroLiquidity, FHE.add(oneForZeroLiquidity, _liquidity));

        // - add contract allowances
        // NOTE: do not allow sender to access total liquidity of current epoch
        FHE.allowThis(zeroForOneEpochs[zeroForOneEpoch].totalLiquidity);
        FHE.allowThis(oneForZeroEpochs[oneForZeroEpoch].totalLiquidity);

        euint128 token0Amount = FHE.select(_zeroForOne, _liquidity, ZERO);
        euint128 token1Amount = FHE.select(_zeroForOne, ZERO, _liquidity);

        // "send" both tokens, one amount is encrypted zero to obscure trade direction
        IFHERC20(Currency.unwrap(key.currency0)).transferFromEncrypted(msg.sender, address(this), token0Amount);
        IFHERC20(Currency.unwrap(key.currency1)).transferFromEncrypted(msg.sender, address(this), token1Amount);
    }

    function _beforeSwap(address, PoolKey calldata key, SwapParams calldata, bytes calldata)
        internal
        override
        returns (bytes4, BeforeSwapDelta, uint24)
    {
        return (BaseHook.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
    }

    function _afterSwap(address, PoolKey calldata key, SwapParams calldata, BalanceDelta, bytes calldata)
        internal
        override
        returns (bytes4, int128)
    {
        return (BaseHook.afterSwap.selector, 0);
    }
}
