// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./TaikoL1TestGroupBase.sol";
import "../../contracts/verifiers/libs/LibPublicInput.sol";
import "../../contracts/thirdparty/optimism/Bytes.sol";

contract TaikoL1TestGroup1 is TaikoL1TestGroupBase {
    // Test summary:
    // 1. Alice proposes a block, assigning Bob as the prover.
    // 2. Bob proves the block within the proving window, using the correct parent hash.
    // 3. Bob's proof is used to verify the block.
    function test_taikoL1_group_1_case_1() external {
        vm.warp(1_000_000);
        printBlockAndTrans(0);

        giveEthAndTko(Alice, 10_000 ether, 1000 ether);
        giveEthAndTko(Bob, 10_000 ether, 1000 ether);
        giveEthAndTko(Taylor, 10_000 ether, 1000 ether);
        ITierProvider.Tier memory tierOp = TestTierProvider(cp).getTier(LibTiers.TIER_OPTIMISTIC);

        console2.log("====== Alice propose a block with bob as the assigned prover");
        TaikoData.BlockMetadata memory meta = proposeBlock(Alice, Bob, "");

        uint96 livenessBond = L1.getConfig().livenessBond;
        uint256 proposedAt;
        {
            printBlockAndTrans(meta.id);
            TaikoData.Block memory blk = L1.getBlock(meta.id);
            assertEq(meta.minTier, LibTiers.TIER_OPTIMISTIC);

            assertEq(blk.nextTransitionId, 1);
            assertEq(blk.verifiedTransitionId, 0);
            assertEq(blk.proposedAt, block.timestamp);
            assertEq(blk.assignedProver, Bob);
            assertEq(blk.livenessBond, livenessBond);

            proposedAt = blk.proposedAt;

            assertEq(tko.balanceOf(Alice), 10_000 ether);
            assertEq(tko.balanceOf(Bob), 10_000 ether - livenessBond);
        }

        // Prove the block
        bytes32 parentHash = GENESIS_BLOCK_HASH;
        bytes32 blockHash = bytes32(uint256(10));
        bytes32 stateRoot = bytes32(uint256(11));

        console2.log("====== Taylor cannot prove the block in the proving window");
        mineAndWrap(10 seconds);
        proveBlock(
            Taylor,
            meta,
            parentHash,
            blockHash,
            stateRoot,
            meta.minTier,
            TaikoErrors.L1_NOT_ASSIGNED_PROVER.selector
        );

        console2.log("====== Bob proves the block");
        mineAndWrap(10 seconds);
        proveBlock(Bob, meta, parentHash, blockHash, stateRoot, meta.minTier, "");

        uint256 provenAt;

        {
            printBlockAndTrans(meta.id);

            TaikoData.Block memory blk = L1.getBlock(meta.id);
            assertEq(blk.nextTransitionId, 2);
            assertEq(blk.verifiedTransitionId, 0);
            assertEq(blk.proposedAt, proposedAt);
            assertEq(blk.assignedProver, Bob);
            assertEq(blk.livenessBond, 0);

            TaikoData.TransitionState memory ts = L1.getTransition(meta.id, 1);
            assertEq(ts.blockHash, blockHash);
            assertEq(ts.stateRoot, stateRoot);
            assertEq(ts.tier, LibTiers.TIER_OPTIMISTIC);
            assertEq(ts.contester, address(0));
            assertEq(ts.contestBond, 1); // not zero
            assertEq(ts.prover, Bob);
            assertEq(ts.validityBond, tierOp.validityBond);
            assertEq(ts.timestamp, block.timestamp);

            provenAt = ts.timestamp;

            assertEq(tko.balanceOf(Bob), 10_000 ether - tierOp.validityBond);
        }

        console2.log("====== Verify block");
        mineAndWrap(7 days);
        verifyBlock(1);
        {
            printBlockAndTrans(meta.id);

            TaikoData.Block memory blk = L1.getBlock(meta.id);
            assertEq(blk.nextTransitionId, 2);
            assertEq(blk.verifiedTransitionId, 1);
            assertEq(blk.proposedAt, proposedAt);
            assertEq(blk.assignedProver, Bob);
            assertEq(blk.livenessBond, 0);

            TaikoData.TransitionState memory ts = L1.getTransition(meta.id, 1);
            assertEq(ts.blockHash, blockHash);
            assertEq(ts.stateRoot, stateRoot);
            assertEq(ts.tier, LibTiers.TIER_OPTIMISTIC);
            assertEq(ts.contester, address(0));
            assertEq(ts.contestBond, 1); // not zero
            assertEq(ts.prover, Bob);
            assertEq(ts.validityBond, tierOp.validityBond);
            assertEq(ts.timestamp, provenAt);

            assertEq(tko.balanceOf(Bob), 10_000 ether);
        }
    }

    // Test summary:
    // 1. Alice proposes a block, assigning Bob as the prover.
    // 2. Taylor proposes the block outside the proving window.
    // 3. Taylor's proof is used to verify the block.
    function test_taikoL1_group_1_case_2() external {
        vm.warp(1_000_000);
        printBlockAndTrans(0);

        giveEthAndTko(Alice, 10_000 ether, 1000 ether);
        giveEthAndTko(Bob, 10_000 ether, 1000 ether);
        giveEthAndTko(Taylor, 10_000 ether, 1000 ether);
        ITierProvider.Tier memory tierOp = TestTierProvider(cp).getTier(LibTiers.TIER_OPTIMISTIC);

        console2.log("====== Alice propose a block with bob as the assigned prover");
        TaikoData.BlockMetadata memory meta = proposeBlock(Alice, Bob, "");

        uint96 livenessBond = L1.getConfig().livenessBond;
        uint256 proposedAt;
        {
            printBlockAndTrans(meta.id);
            TaikoData.Block memory blk = L1.getBlock(meta.id);
            assertEq(meta.minTier, LibTiers.TIER_OPTIMISTIC);

            assertEq(blk.nextTransitionId, 1);
            assertEq(blk.verifiedTransitionId, 0);
            assertEq(blk.proposedAt, block.timestamp);
            assertEq(blk.assignedProver, Bob);
            assertEq(blk.livenessBond, livenessBond);

            proposedAt = blk.proposedAt;

            assertEq(tko.balanceOf(Alice), 10_000 ether);
            assertEq(tko.balanceOf(Bob), 10_000 ether - livenessBond);
        }

        // Prove the block
        bytes32 parentHash = GENESIS_BLOCK_HASH;
        bytes32 blockHash = bytes32(uint256(10));
        bytes32 stateRoot = bytes32(uint256(11));

        console2.log("====== Taylor proves the block");
        mineAndWrap(7 days);
        proveBlock(Taylor, meta, parentHash, blockHash, stateRoot, meta.minTier, "");

        uint256 provenAt;

        {
            printBlockAndTrans(meta.id);

            TaikoData.Block memory blk = L1.getBlock(meta.id);
            assertEq(blk.nextTransitionId, 2);
            assertEq(blk.verifiedTransitionId, 0);
            assertEq(blk.proposedAt, proposedAt);
            assertEq(blk.assignedProver, Bob);
            assertEq(blk.livenessBond, 0);

            TaikoData.TransitionState memory ts = L1.getTransition(meta.id, 1);
            assertEq(ts.blockHash, blockHash);
            assertEq(ts.stateRoot, stateRoot);
            assertEq(ts.tier, LibTiers.TIER_OPTIMISTIC);
            assertEq(ts.contester, address(0));
            assertEq(ts.contestBond, 1); // not zero
            assertEq(ts.prover, Taylor);
            assertEq(ts.validityBond, tierOp.validityBond);
            assertEq(ts.timestamp, block.timestamp);

            provenAt = ts.timestamp;

            assertEq(tko.balanceOf(Bob), 10_000 ether - livenessBond);
            assertEq(tko.balanceOf(Taylor), 10_000 ether - tierOp.validityBond);
        }

        console2.log("====== Verify block");
        mineAndWrap(7 days);
        verifyBlock(1);
        {
            printBlockAndTrans(meta.id);

            TaikoData.Block memory blk = L1.getBlock(meta.id);
            assertEq(blk.nextTransitionId, 2);
            assertEq(blk.verifiedTransitionId, 1);
            assertEq(blk.proposedAt, proposedAt);
            assertEq(blk.assignedProver, Bob);
            assertEq(blk.livenessBond, 0);

            TaikoData.TransitionState memory ts = L1.getTransition(meta.id, 1);
            assertEq(ts.blockHash, blockHash);
            assertEq(ts.stateRoot, stateRoot);
            assertEq(ts.tier, LibTiers.TIER_OPTIMISTIC);
            assertEq(ts.contester, address(0));
            assertEq(ts.contestBond, 1); // not zero
            assertEq(ts.prover, Taylor);
            assertEq(ts.validityBond, tierOp.validityBond);
            assertEq(ts.timestamp, provenAt);

            assertEq(tko.balanceOf(Bob), 10_000 ether - livenessBond);
            assertEq(tko.balanceOf(Taylor), 10_000 ether);
        }
    }

    // Test summary:
    // 1. Alice proposes a block, assigning Bob as the prover.
    // 2. Bob proves the block within the proving window.
    // 3. Taylor proves the block outside the proving window.
    // 4. Taylor's proof is used to verify the block.
    function test_taikoL1_group_1_case_3() external {
        vm.warp(1_000_000);
        giveEthAndTko(Alice, 10_000 ether, 1000 ether);
        giveEthAndTko(Bob, 10_000 ether, 1000 ether);
        giveEthAndTko(Taylor, 10_000 ether, 1000 ether);
        ITierProvider.Tier memory tierOp = TestTierProvider(cp).getTier(LibTiers.TIER_OPTIMISTIC);

        console2.log("====== Alice propose a block with bob as the assigned prover");
        TaikoData.BlockMetadata memory meta = proposeBlock(Alice, Bob, "");

        // Prove the block
        bytes32 parentHash1 = bytes32(uint256(9));
        bytes32 parentHash2 = GENESIS_BLOCK_HASH;
        bytes32 blockHash = bytes32(uint256(10));
        bytes32 stateRoot = bytes32(uint256(11));

        mineAndWrap(10 seconds);

        console2.log("====== Bob proves the block first");
        proveBlock(Bob, meta, parentHash1, blockHash, stateRoot, meta.minTier, "");

        console2.log("====== Taylor proves the block later");
        mineAndWrap(10 seconds);
        proveBlock(Taylor, meta, parentHash2, blockHash, stateRoot, meta.minTier, "");

        console2.log("====== Verify block");
        mineAndWrap(7 days);
        verifyBlock(1);
        {
            printBlockAndTrans(meta.id);

            TaikoData.Block memory blk = L1.getBlock(meta.id);
            assertEq(blk.nextTransitionId, 3);
            assertEq(blk.verifiedTransitionId, 2);
            assertEq(blk.assignedProver, Bob);
            assertEq(blk.livenessBond, 0);

            TaikoData.TransitionState memory ts = L1.getTransition(meta.id, 2);
            assertEq(ts.contester, address(0));
            assertEq(ts.contestBond, 1); // not zero
            assertEq(ts.prover, Taylor);
            assertEq(ts.validityBond, tierOp.validityBond);

            assertEq(tko.balanceOf(Bob), 10_000 ether - tierOp.validityBond);
            assertEq(tko.balanceOf(Taylor), 10_000 ether);
        }
    }

    // Test summary:
    // 1. Alice proposes a block, assigning Bob as the prover.
    // 2. Bob proves the block within the proving window.
    // 3. Taylor proves the block outside the proving window.
    // 4. Bob's proof is used to verify the block.
    function test_taikoL1_group_1_case_4() external {
        vm.warp(1_000_000);
        giveEthAndTko(Alice, 10_000 ether, 1000 ether);
        giveEthAndTko(Bob, 10_000 ether, 1000 ether);
        giveEthAndTko(Taylor, 10_000 ether, 1000 ether);
        ITierProvider.Tier memory tierOp = TestTierProvider(cp).getTier(LibTiers.TIER_OPTIMISTIC);

        console2.log("====== Alice propose a block with bob as the assigned prover");
        TaikoData.BlockMetadata memory meta = proposeBlock(Alice, Bob, "");

        // Prove the block
        bytes32 parentHash1 = GENESIS_BLOCK_HASH;
        bytes32 parentHash2 = bytes32(uint256(9));
        bytes32 blockHash = bytes32(uint256(10));
        bytes32 stateRoot = bytes32(uint256(11));

        mineAndWrap(10 seconds);

        console2.log("====== Bob proves the block first");
        proveBlock(Bob, meta, parentHash1, blockHash, stateRoot, meta.minTier, "");

        console2.log("====== Taylor proves the block later");
        mineAndWrap(10 seconds);
        proveBlock(Taylor, meta, parentHash2, blockHash, stateRoot, meta.minTier, "");

        console2.log("====== Verify block");
        mineAndWrap(7 days);
        verifyBlock(1);
        {
            printBlockAndTrans(meta.id);

            TaikoData.Block memory blk = L1.getBlock(meta.id);
            assertEq(blk.nextTransitionId, 3);
            assertEq(blk.verifiedTransitionId, 1);
            assertEq(blk.assignedProver, Bob);
            assertEq(blk.livenessBond, 0);

            TaikoData.TransitionState memory ts = L1.getTransition(meta.id, 1);
            assertEq(ts.contester, address(0));
            assertEq(ts.contestBond, 1); // not zero
            assertEq(ts.prover, Bob);
            assertEq(ts.validityBond, tierOp.validityBond);

            assertEq(tko.balanceOf(Bob), 10_000 ether);
            assertEq(tko.balanceOf(Taylor), 10_000 ether - tierOp.validityBond);
        }
    }

    // Test summary:
    // 1. Alice proposes a block, assigning Bob as the prover.
    // 2. William proves the block outside the proving window.
    // 3. Taylor also proves the block outside the proving window.
    // 4. Taylor's proof is used to verify the block.
    function test_taikoL1_group_1_case_5() external {
        vm.warp(1_000_000);
        giveEthAndTko(Alice, 10_000 ether, 1000 ether);
        giveEthAndTko(Bob, 10_000 ether, 1000 ether);
        giveEthAndTko(Taylor, 10_000 ether, 1000 ether);
        giveEthAndTko(William, 10_000 ether, 1000 ether);
        ITierProvider.Tier memory tierOp = TestTierProvider(cp).getTier(LibTiers.TIER_OPTIMISTIC);

        console2.log("====== Alice propose a block with bob as the assigned prover");
        TaikoData.BlockMetadata memory meta = proposeBlock(Alice, Bob, "");

        // Prove the block
        bytes32 parentHash1 = bytes32(uint256(9));
        bytes32 parentHash2 = GENESIS_BLOCK_HASH;
        bytes32 blockHash = bytes32(uint256(10));
        bytes32 stateRoot = bytes32(uint256(11));

        mineAndWrap(7 days);

        console2.log("====== William proves the block first");
        proveBlock(William, meta, parentHash1, blockHash, stateRoot, meta.minTier, "");

        console2.log("====== Taylor proves the block later");
        mineAndWrap(10 seconds);
        proveBlock(Taylor, meta, parentHash2, blockHash, stateRoot, meta.minTier, "");

        console2.log("====== Verify block");
        mineAndWrap(7 days);
        verifyBlock(1);
        {
            printBlockAndTrans(meta.id);

            TaikoData.Block memory blk = L1.getBlock(meta.id);
            assertEq(blk.nextTransitionId, 3);
            assertEq(blk.verifiedTransitionId, 2);
            assertEq(blk.assignedProver, Bob);
            assertEq(blk.livenessBond, 0);

            TaikoData.TransitionState memory ts = L1.getTransition(meta.id, 2);
            assertEq(ts.contester, address(0));
            assertEq(ts.contestBond, 1); // not zero
            assertEq(ts.prover, Taylor);
            assertEq(ts.validityBond, tierOp.validityBond);

            assertEq(tko.balanceOf(Bob), 10_000 ether - L1.getConfig().livenessBond);
            assertEq(tko.balanceOf(Taylor), 10_000 ether);
        }
    }
    // Test summary:
    // 1. Alice proposes a block, assigning Bob as the prover.
    // 2. Bob proves the block outside the proving window, using the correct parent hash.
    // 3. Bob's proof is used to verify the block.

    function test_taikoL1_group_1_case_6() external {
        vm.warp(1_000_000);
        printBlockAndTrans(0);

        giveEthAndTko(Alice, 10_000 ether, 1000 ether);
        giveEthAndTko(Bob, 10_000 ether, 1000 ether);
        giveEthAndTko(Taylor, 10_000 ether, 1000 ether);
        ITierProvider.Tier memory tierOp = TestTierProvider(cp).getTier(LibTiers.TIER_OPTIMISTIC);

        console2.log("====== Alice propose a block with bob as the assigned prover");
        TaikoData.BlockMetadata memory meta = proposeBlock(Alice, Bob, "");

        uint96 livenessBond = L1.getConfig().livenessBond;
        uint256 proposedAt;
        {
            printBlockAndTrans(meta.id);
            TaikoData.Block memory blk = L1.getBlock(meta.id);
            assertEq(meta.minTier, LibTiers.TIER_OPTIMISTIC);

            assertEq(blk.nextTransitionId, 1);
            assertEq(blk.verifiedTransitionId, 0);
            assertEq(blk.proposedAt, block.timestamp);
            assertEq(blk.assignedProver, Bob);
            assertEq(blk.livenessBond, livenessBond);

            proposedAt = blk.proposedAt;

            assertEq(tko.balanceOf(Alice), 10_000 ether);
            assertEq(tko.balanceOf(Bob), 10_000 ether - livenessBond);
        }

        // Prove the block
        bytes32 parentHash = GENESIS_BLOCK_HASH;
        bytes32 blockHash = bytes32(uint256(10));
        bytes32 stateRoot = bytes32(uint256(11));

        console2.log("====== Bob proves the block outside the proving window");
        mineAndWrap(7 days);
        proveBlock(Bob, meta, parentHash, blockHash, stateRoot, meta.minTier, "");

        uint256 provenAt;

        {
            printBlockAndTrans(meta.id);

            TaikoData.Block memory blk = L1.getBlock(meta.id);
            assertEq(blk.nextTransitionId, 2);
            assertEq(blk.verifiedTransitionId, 0);
            assertEq(blk.proposedAt, proposedAt);
            assertEq(blk.assignedProver, Bob);
            assertEq(blk.livenessBond, 0);

            TaikoData.TransitionState memory ts = L1.getTransition(meta.id, 1);
            assertEq(ts.blockHash, blockHash);
            assertEq(ts.stateRoot, stateRoot);
            assertEq(ts.tier, LibTiers.TIER_OPTIMISTIC);
            assertEq(ts.contester, address(0));
            assertEq(ts.contestBond, 1); // not zero
            assertEq(ts.prover, Bob);
            assertEq(ts.validityBond, tierOp.validityBond);
            assertEq(ts.timestamp, block.timestamp);

            provenAt = ts.timestamp;

            assertEq(tko.balanceOf(Bob), 10_000 ether - tierOp.validityBond - livenessBond);
        }

        console2.log("====== Verify block");
        mineAndWrap(7 days);
        verifyBlock(1);
        {
            printBlockAndTrans(meta.id);

            TaikoData.Block memory blk = L1.getBlock(meta.id);
            assertEq(blk.nextTransitionId, 2);
            assertEq(blk.verifiedTransitionId, 1);
            assertEq(blk.proposedAt, proposedAt);
            assertEq(blk.assignedProver, Bob);
            assertEq(blk.livenessBond, 0);

            TaikoData.TransitionState memory ts = L1.getTransition(meta.id, 1);
            assertEq(ts.blockHash, blockHash);
            assertEq(ts.stateRoot, stateRoot);
            assertEq(ts.tier, LibTiers.TIER_OPTIMISTIC);
            assertEq(ts.contester, address(0));
            assertEq(ts.contestBond, 1); // not zero
            assertEq(ts.prover, Bob);
            assertEq(ts.validityBond, tierOp.validityBond);
            assertEq(ts.timestamp, provenAt);

            assertEq(tko.balanceOf(Bob), 10_000 ether - livenessBond);
        }
    }

    // Test summary:
    // 1. Alice proposes a block, assigning herself as the prover.
    function test_taikoL1_group_1_case_7_no_hooks() external {
        vm.warp(1_000_000);
        printBlockAndTrans(0);

        giveEthAndTko(Alice, 10_000 ether, 1000 ether);

        console2.log("====== Alice propose a block with herself as the assigned prover");
        TaikoData.BlockMetadata memory meta = proposeBlock(Alice, Alice, "");

        uint96 livenessBond = L1.getConfig().livenessBond;
        uint256 proposedAt;
        {
            printBlockAndTrans(meta.id);
            TaikoData.Block memory blk = L1.getBlock(meta.id);
            assertEq(meta.minTier, LibTiers.TIER_OPTIMISTIC);

            assertEq(blk.nextTransitionId, 1);
            assertEq(blk.verifiedTransitionId, 0);
            assertEq(blk.proposedAt, block.timestamp);
            assertEq(blk.assignedProver, Alice);
            assertEq(blk.livenessBond, livenessBond);

            proposedAt = blk.proposedAt;

            assertEq(tko.balanceOf(Alice), 10_000 ether - livenessBond);
        }
    }

    // Test decode prove_block's input
    function test_decode_prove_block_input() external {
        bytes memory _input =
            hex"652411efdb9eaea87619503d49793a882d0607695ab1a61842c7a643bf46e1c7f5850f9bbb8fefc2c39ec2e4461453377e204fd62285a4ec5f764b29a02d97fa0195cff36ba33eeef55a8e24f2bcbf17a1b06247a57b59633b6e7aa6e46427e0302e31382e302d64657600000000000000000000000000000000000000000000569e75fc77c1a856f6daaf9e69d8a9566ca34aa47f9133711ce065a571af0cfd000000000000000000000000000000633b68f5d8d3a86593ebb815b4663bcbe00000000000000000000000000000000000000000000000000000000000000108000000000000000000000000000000000000000000000000000000000e4e1c000000000000000000000000000000000000000000000000000000000066547787000000000000000000000000000000000000000000000000000000000130951300000000000000000000000000000000000000000000000000000000000000c8000000000000000000000000000000000000000000000000000000000000000100cb85539d227ff61504d9146c998bdeb8de279404f12b3e27355ec0015a74d7000000000000000000000000000000633b68f5d8d3a86593ebb815b4663bcbe0002a972756335d82850f3fedca7c06c3520634f4ea986376a88d3749fff8f642ac9254c7141eba2cfa120c821d49aa9b33398c7b2c782f8cd5beff572777f379f0a66d292e20b7e019a27083c9b92924e86c7aa1ace0c2806af7d7547e685c7f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000026000000000000000000000000000000000000000000000000000000000000000c80000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000005900000004f02099f42d499028ca52a5205d4e21001f5e3525f8abb7f54e6532832ad6c97dd5f167335963afd029f71650b8cb5f71d726706e575c8020a9ffb979b5e1811aa87ef25a5108d4670c53017d7efbbc784230a2831c00000000000000";

        (
            TaikoData.BlockMetadata memory meta,
            TaikoData.Transition memory tran,
            TaikoData.TierProof memory proof
        ) = abi.decode(_input, (TaikoData.BlockMetadata, TaikoData.Transition, TaikoData.TierProof));

        console2.log("meta:");
        console2.logBytes32(meta.l1Hash);
        console2.logBytes32(meta.difficulty);
        console2.logBytes32(meta.blobHash);
        console2.logBytes32(meta.extraData);
        console2.logBytes32(meta.depositsHash);
        console2.logAddress(meta.coinbase);
        console2.log(meta.id);
        console2.log(meta.gasLimit);
        console2.log(meta.timestamp);
        console2.log(meta.l1Height);
        console2.log(meta.minTier);
        console2.log(meta.blobUsed);
        console2.logBytes32(meta.parentMetaHash);
        console2.logAddress(meta.sender);

        console2.log("trans:");
        console2.logBytes32(tran.parentHash);
        console2.logBytes32(tran.blockHash);
        console2.logBytes32(tran.stateRoot);
        console2.logBytes32(tran.graffiti);

        console2.log("proof:");
        console2.log(proof.tier);
        console2.logBytes(proof.data);

        bytes32 metaHash = keccak256(abi.encode(meta));
        address sgx_instance = address(bytes20(Bytes.slice(proof.data, 4, 20)));
        console2.log("sgx_instance is:");
        console2.logAddress(sgx_instance);
        bytes32 piHash = LibPublicInput.hashPublicInputs(
            tran,
            0xb0f3186FC1963f774f52ff455DC86aEdD0b31F81,
            sgx_instance,
            0x68d30f47F19c07bCCEf4Ac7FAE2Dc12FCa3e0dC9,
            metaHash,
            167_000
        );
        console2.log("pi hash is:");
        console2.logBytes32(piHash);

        bytes memory proofData = Bytes.slice(proof.data, 24, 65);
        address oldInstance = ECDSA.recover(piHash, proofData);
        console2.logAddress(oldInstance);
        assertEq(oldInstance, sgx_instance);
    }
}
