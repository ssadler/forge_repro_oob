// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

/*
 * This contract is designed to help a user perform multiple
 * authenticated calls to different contracts in one transaction.
 *
 * In order for applications to authenticate a user calling via this contract,
 * they use the getCaller method, which will return the original msg.sender.
 *
 * Security of this contract depends on not being able to spoof the sender address.
 * It is easy to verify that the sender address is set, once, to msg.sender,
 * near the start of the proxy entry point.
 *
 */

contract AuthProxy {

  bytes32 constant SLOT_USER = "authProxy.user";
  bytes32 constant SLOT_APP = "authProxy.app";

  struct Call {
    address target;
    bytes callData;
    uint copyWords;
    uint value;
  }

  /*
   * Proxy a call
   */
  function proxy(Call[] memory calls) external payable returns (bytes[] memory) {

    // Check that proxy isnt already in use
    bool canProxy;
    assembly { canProxy := iszero(tload(SLOT_USER)) }
    require(canProxy, "auth in use");

    // Set the user so that downstream calls can find the original caller
    assembly { tstore(SLOT_USER, caller()) }

    // Create the outputs array and run each call
    bytes[] memory outputs = new bytes[](calls.length);
    for (uint i=0; i<calls.length; i++) {
      runCall(calls[i], i, outputs);
    }

    // clear for next time
    assembly {
      tstore(SLOT_USER, 0)
      tstore(SLOT_APP, 0)
    }

    return outputs;
  }

  /*
   * Run a call
   */
  function runCall(Call memory call, uint i, bytes[] memory outputs) internal {

    // Check if target refers to a previous output
    address target = call.target;
    if (uint160(target) < i) {
      bytes memory output = outputs[uint160(target)];
      require(output.length > 0, "AuthProxy: replacement target is empty");
      target = abi.decode(output, (address));
    }

    bytes memory callData = buildCallData(call, i, outputs);

    assembly { tstore(SLOT_APP, target) }

    (bool ok, bytes memory rdata) = target.call{value: call.value}(callData);

    if (!ok) {
      assembly { revert(add(rdata, 32), mload(rdata)) }
    }

    outputs[i] = rdata;
  }

  /*
   * Optionally append arguments (data returned from previous calls) to calldata.
   *
   * Note, that this may not compose in the presence of dynamically sized types.
   */
  function buildCallData(Call memory call, uint i, bytes[] memory outputs)
    internal pure returns (bytes memory)
  {
    bytes memory callData = call.callData;

    if (call.copyWords > 0) {

      // Get calldata length
      uint cdLen = callData.length % 32;
      require(cdLen == 0 || cdLen == 4, "unknown calldata format");

      // Copy copyWords
      uint copyWords = call.copyWords;

      while (copyWords > 0) {

        if (copyWords & 0xFFFF == 0xFFFF) {
          break;
        }
        uint destWord = copyWords & 31;
        copyWords >>= 5;
        uint sourceWord = copyWords & 31;
        copyWords >>= 5;
        uint resultIndex = copyWords & 63;
        copyWords >>= 6;

        require(resultIndex < i, "proxyAuth invalid arg index");
        bytes memory output = outputs[resultIndex];

        require(sourceWord * 32 + 32 <= output.length, "proxyAuth invalid arg offset");
        // TODO: require target offset sanity

        assembly {
          mstore(
            add(add(callData, add(cdLen, 32)), mul(destWord, 32)),
            mload(add(add(output, 32), mul(sourceWord, 32)))
          )
        }
      }
    }

    return callData;
  }

  /*
   * Allow callee (and only callee) to get the original caller
   */
  function getCaller() external view returns (address caller_) {
    assembly {
      if eq(caller(), tload(SLOT_APP)) {
        caller_ := tload(SLOT_USER)
      }
    }
  }
}

contract AuthProxyClient {
  AuthProxy immutable _authProxy;

  constructor(AuthProxy authProxy) {
    _authProxy = authProxy;
  }

  function getAuthedSender() internal view returns (address) {
    if (msg.sender == address(_authProxy)) {
      return _authProxy.getCaller();
    }

    return msg.sender;
  }
}
