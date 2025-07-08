// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import {Token} from "../src/Token.sol";

contract TokenScript is Script {
    function setUp() public {}

    function run() public returns(Token t0, Token t1){
        vm.startBroadcast();
        t0 = new Token("Mask", "MSK");
        t1 = new Token("Cipher", "CPH"); 

        //stack up the bagsss
        t0.mint(msg.sender, 1e50);
        t1.mint(msg.sender, 1e50);
        
        vm.stopBroadcast();
    }
}