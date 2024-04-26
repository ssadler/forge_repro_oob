// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;


import "../src/AuthProxy.sol";
import "forge-std/Test.sol";


contract Repro is Test {

  AuthProxy _authProxy = new AuthProxy();

  function createBeastie() internal {
    AuthProxy.Call[] memory calls = new AuthProxy.Call[](1);

    calls[0] = AuthProxy.Call(
      address(this),
      abi.encodeCall(Repro.place, ()),
      0, 0
    );

    bytes[] memory outputs = _authProxy.proxy(calls);

    abi.decode(outputs[0], (address));
  }

  function place() external pure {
    revert("invalid board");
  }
}



contract TestFakers is Repro {
  function test_ok() public {
    vm.expectRevert("invalid board");
    createBeastie();
  }
}
