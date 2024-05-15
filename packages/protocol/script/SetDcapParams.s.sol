// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/src/Script.sol";
import "forge-std/src/console2.sol";

import "../contracts/verifiers/SgxVerifier.sol";
import "../test/automata-attestation/common/AttestationBase.t.sol";
import { AutomataDcapV3Attestation } from
    "../contracts/automata-attestation/AutomataDcapV3Attestation.sol";
import "../contracts/automata-attestation/lib/EnclaveIdStruct.sol";
import { ISigVerifyLib } from "../contracts/automata-attestation/interfaces/ISigVerifyLib.sol";

contract SetDcapParams is Script, AttestationBase {
    uint256 public ownerPrivateKey = vm.envUint("PRIVATE_KEY"); // Owner of the attestation contract
    address public dcapAttestationAddress = vm.envAddress("ATTESTATION_ADDRESS");
    address public sgxVerifier = vm.envAddress("SGX_VERIFIER_ADDRESS");
    address public pemCertChainLibAddr = vm.envAddress("PEM_CERTCHAIN_ADDRESS");
    // TASK_FLAG:
    // [setMrEnclave,setMrSigner,configQE,configTCB,enableMrCheck,registerSgxInstanceWithQuote]
    uint256[] internal defaultTaskFlags = [1, 1, 1, 1, 1, 1];
    uint256[] public taskFlags = vm.envOr("TASK_ENABLE", ",", defaultTaskFlags);

    function run() external {
        require(ownerPrivateKey != 0, "PRIVATE_KEY not set");
        require(dcapAttestationAddress != address(0), "ATTESTATION_ADDRESS not set");

        vm.startBroadcast(ownerPrivateKey);
        if (taskFlags[0] != 0) {
            bool enable = (taskFlags[0] == 1);
            _setMrEnclave(enable);
        }
        if (taskFlags[1] != 0) {
            bool enable = (taskFlags[1] == 1);
            _setMrSigner(enable);
        }
        if (taskFlags[2] != 0) {
            _configureQeIdentityJson();
        }
        if (taskFlags[3] != 0) {
            _configureTcbInfoJson();
        }
        if (taskFlags[4] != 0) {
            toggleCheckQuoteValidity(dcapAttestationAddress);
        }
        if (taskFlags[5] != 0) {
            _registerSgxInstanceWithQuoteBytes();
        }

        vm.stopBroadcast();
    }

    function _setMrEnclave(bool enable) internal {
        mrEnclave = vm.envBytes32("MR_ENCLAVE");
        console2.log("_setMrEnclave set: ", uint256(mrEnclave));
        setMrEnclave(dcapAttestationAddress, mrEnclave, enable);
        console2.log("MR_ENCLAVE set: ", uint256(mrEnclave));
    }

    function _setMrSigner(bool enable) internal {
        mrSigner = vm.envBytes32("MR_SIGNER");
        setMrSigner(dcapAttestationAddress, mrSigner, enable);
        console2.log("MR_SIGNER set: ", uint256(mrSigner));
    }

    function _configureQeIdentityJson() internal {
        idPath = vm.envString("QEID_PATH");
        string memory enclaveIdJson = vm.readFile(string.concat(vm.projectRoot(), idPath));
        configureQeIdentityJson(dcapAttestationAddress, enclaveIdJson);
        console2.log("QE_IDENTITY_JSON set:");
        console2.logString(enclaveIdJson);
    }

    function _configureTcbInfoJson() internal {
        tcbInfoPath = vm.envString("TCB_INFO_PATH");
        string memory tcbInfoJson = vm.readFile(string.concat(vm.projectRoot(), tcbInfoPath));
        configureTcbInfoJson(dcapAttestationAddress, tcbInfoJson);
        console2.logString("TCB_INFO_JSON set: ");
        console2.logString(tcbInfoJson);
    }

    function _registerSgxInstanceWithQuoteBytes() internal {
        bytes memory v3QuoteBytes = vm.envBytes("V3_QUOTE_BYTES");
        registerSgxInstanceWithQuoteBytes(pemCertChainLibAddr, sgxVerifier, v3QuoteBytes);
    }

    function do_sth() internal {
        AutomataDcapV3Attestation autoAttestation =
            AutomataDcapV3Attestation(dcapAttestationAddress);

        // V3Struct.ParsedV3QuoteStruct memory v3quote = ParseV3QuoteBytes(pemCertChainLibAddr,
        // v3QuoteBytes);
        // (bool verified,) = autoAttestation.verifyParsedQuote(v3quote);
        // assertEq(verified, true);

        // query automata
        console2.log("qe = ");
        console2.logAddress(address(autoAttestation.sigVerifyLib()));
        console2.logAddress(address(autoAttestation.pemCertLib()));

        (bytes4 a, bytes4 b, uint16 c, bytes16 d, bytes16 e, bytes32 f) =
            autoAttestation.qeIdentity();
        console2.logBytes4(a);
        console2.logBytes4(b);
        console2.logUint(c);
        console2.logBytes16(d);
        console2.logBytes16(e);
        console2.logBytes32(f);

        // mapping(string => TCBInfoStruct.TCBInfo) storage kv =
        (string memory pceid, string memory fmspc) = autoAttestation.tcbInfo("00606a000000");
        console2.logString(pceid);
        console2.logString(fmspc);

        (string memory pceid1, string memory fmspc1) = autoAttestation.tcbInfo("00906ed50000");
        console2.logString(pceid1);
        console2.logString(fmspc1);

        (string memory pceid2, string memory fmspc2) = autoAttestation.tcbInfo("00a067110000");
        console2.logString(pceid2);
        console2.logString(fmspc2);

        // query sgx verifier
        (address sgxVerifierAddr, uint64 vs) = SgxVerifier(sgxVerifier).instances(0x0);
        console2.logAddress(sgxVerifierAddr);
    }
}
