// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {IERC20} from "forge-std/interfaces/IERC20.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {Currency} from "@uniswap/v4-core/src/types/Currency.sol";

/// @notice Shared configuration between scripts
contract Config {
    /// @dev populated with default anvil addresses
    IERC20 constant token0 = IERC20(address(0x09fc36Bb906cB720037232697624bcAc48a4a21F));       // Cipher Token (CPH)
    IERC20 constant token1 = IERC20(address(0x988E23405b307E59c0B63c71191FEB8681C15097));       // Mask Token (MSK)
    IHooks constant hookContract = IHooks(address(0x34DEb2a90744fC6F2F133140dC69952Bb39CC080)); // Market Order Hook

    Currency constant currency0 = Currency.wrap(address(token0));
    Currency constant currency1 = Currency.wrap(address(token1));
}
