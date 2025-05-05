// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/Counter.sol";

contract CounterTest is Test {
    Counter public counter;

    function setUp() public {
        counter = new Counter();
    }

    function testNormalIncrement() public {
        counter.increment();
        assertEq(counter.count(), 1);
    }

    function testCorruptedCalldata() public {
        // Manually craft corrupted calldata
        bytes memory corrupted = hex"d09de08affff0000"; // increment() selector with padding
        (bool success, ) = address(counter).call(corrupted);

        // The call succeeds, but count may not change
        assertTrue(success, "Call should not revert");
        assertEq(counter.count(), 0, "Count should not change if calldata is malformed");
    }
}
