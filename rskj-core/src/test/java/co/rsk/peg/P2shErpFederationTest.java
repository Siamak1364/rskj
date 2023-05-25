package co.rsk.peg;

import co.rsk.bitcoinj.core.Address;
import co.rsk.bitcoinj.core.BtcECKey;
import co.rsk.bitcoinj.core.BtcTransaction;
import co.rsk.bitcoinj.core.Coin;
import co.rsk.bitcoinj.core.NetworkParameters;
import co.rsk.bitcoinj.core.Sha256Hash;
import co.rsk.bitcoinj.core.Utils;
import co.rsk.bitcoinj.crypto.TransactionSignature;
import co.rsk.bitcoinj.script.Script;
import co.rsk.bitcoinj.script.ScriptBuilder;
import co.rsk.bitcoinj.script.ScriptOpCodes;
import co.rsk.config.BridgeConstants;
import co.rsk.config.BridgeMainNetConstants;
import co.rsk.config.BridgeRegTestConstants;
import co.rsk.config.BridgeTestNetConstants;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import org.bouncycastle.util.encoders.Hex;
import org.ethereum.config.blockchain.upgrades.ActivationConfig;
import org.ethereum.config.blockchain.upgrades.ActivationConfigsForTest;
import org.ethereum.config.blockchain.upgrades.ConsensusRule;
import org.ethereum.crypto.ECKey;
import org.ethereum.crypto.HashUtil;
import org.ethereum.util.ByteUtil;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.List;

import static co.rsk.peg.FederationMember.BTC_RSK_MST_PUBKEYS_COMPARATOR;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class P2shErpFederationTest {

    @Test
    void getRedeemScript_testnet() {
        test_getRedeemScript(BridgeTestNetConstants.getInstance());
    }

    @Test
    void getRedeemScript_mainnet() {
        test_getRedeemScript(BridgeMainNetConstants.getInstance());
    }

    @Test
    void getStandardRedeemscript() {
        List<FederationMember> members = FederationMember.getFederationMembersFromKeys(
                Arrays.asList(new BtcECKey(), new BtcECKey(), new BtcECKey())
        );
        Instant creationTime = Instant.now();
        int creationBlock = 0;
        NetworkParameters btcParams = BridgeRegTestConstants.getInstance().getBtcParams();

        ActivationConfig.ForBlock activations = ActivationConfigsForTest.all().forBlock(0);

        // Create a legacy powpeg and then a p2sh valid one. Both of them should produce the same standard redeem script

        Federation legacyFed = new Federation(
                members,
                creationTime,
                creationBlock,
                btcParams
        );

        P2shErpFederation p2shFed = new P2shErpFederation(
                members,
                creationTime,
                creationBlock,
                btcParams,
                Arrays.asList(new BtcECKey(), new BtcECKey()),
                10_000,
                activations
        );

        assertEquals(legacyFed.getRedeemScript(), p2shFed.getStandardRedeemScript());
        Assertions.assertNotEquals(p2shFed.getRedeemScript(), p2shFed.getStandardRedeemScript());
    }

    @Test
    void getPowPegAddress_testnet() {
        BridgeConstants bridgeTestNetConstants = BridgeTestNetConstants.getInstance();

        List<BtcECKey> powpegKeys = Arrays.stream(new String[]{
            "020ace50bab1230f8002a0bfe619482af74b338cc9e4c956add228df47e6adae1c",
            "0275d473555de2733c47125f9702b0f870df1d817379f5587f09b6c40ed2c6c949",
            "025093f439fb8006fd29ab56605ffec9cdc840d16d2361004e1337a2f86d8bd2db",
            "026b472f7d59d201ff1f540f111b6eb329e071c30a9d23e3d2bcd128fe73dc254c",
            "03250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf93",
            "0357f7ed4c118e581f49cd3b4d9dd1edb4295f4def49d6dcf2faaaaac87a1a0a42",
            "03ae72827d25030818c4947a800187b1fbcc33ae751e248ae60094cc989fb880f6",
            "03e05bf6002b62651378b1954820539c36ca405cbb778c225395dd9ebff6780299",
            "03b58a5da144f5abab2e03e414ad044b732300de52fa25c672a7f7b35888771906"
        }).map(hex -> BtcECKey.fromPublicOnly(Hex.decode(hex))).collect(Collectors.toList());
        Address expectedAddress = Address.fromBase58(
            bridgeTestNetConstants.getBtcParams(),
            "2N7Y1BW8pMLMTQ1fg4kSAftSrwMwpb4S9B7"
        );

        Federation p2shErpFederation = new P2shErpFederation(
            FederationTestUtils.getFederationMembersWithBtcKeys(powpegKeys),
            Instant.now(),
            0L,
            bridgeTestNetConstants.getBtcParams(),
            bridgeTestNetConstants.getErpFedPubKeysList(),
            bridgeTestNetConstants.getErpFedActivationDelay(),
            mock(ActivationConfig.ForBlock.class)
        );

        assertEquals(expectedAddress, p2shErpFederation.getAddress());
    }

    @Test
    void getPowPegAddress_mainnet() {
        BridgeConstants bridgeMainNetConstants = BridgeMainNetConstants.getInstance();

        List<BtcECKey> powpegKeys = Arrays.stream(new String[]{
            "020ace50bab1230f8002a0bfe619482af74b338cc9e4c956add228df47e6adae1c",
            "0275d473555de2733c47125f9702b0f870df1d817379f5587f09b6c40ed2c6c949",
            "025093f439fb8006fd29ab56605ffec9cdc840d16d2361004e1337a2f86d8bd2db",
            "026b472f7d59d201ff1f540f111b6eb329e071c30a9d23e3d2bcd128fe73dc254c",
            "03250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf93",
            "0357f7ed4c118e581f49cd3b4d9dd1edb4295f4def49d6dcf2faaaaac87a1a0a42",
            "03ae72827d25030818c4947a800187b1fbcc33ae751e248ae60094cc989fb880f6",
            "03e05bf6002b62651378b1954820539c36ca405cbb778c225395dd9ebff6780299",
            "03b58a5da144f5abab2e03e414ad044b732300de52fa25c672a7f7b35888771906"
        }).map(hex -> BtcECKey.fromPublicOnly(Hex.decode(hex))).collect(Collectors.toList());
        Address expectedAddress = Address.fromBase58(
            bridgeMainNetConstants.getBtcParams(),
            "35iEoWHfDfEXRQ5ZWM5F6eMsY2Uxrc64YK"
        );

        Federation p2shErpFederation = new P2shErpFederation(
            FederationTestUtils.getFederationMembersWithBtcKeys(powpegKeys),
            Instant.now(),
            0L,
            bridgeMainNetConstants.getBtcParams(),
            bridgeMainNetConstants.getErpFedPubKeysList(),
            bridgeMainNetConstants.getErpFedActivationDelay(),
            mock(ActivationConfig.ForBlock.class)
        );

        assertEquals(expectedAddress, p2shErpFederation.getAddress());
    }

    private void test_getRedeemScript(BridgeConstants bridgeConstants) {
        List<BtcECKey> defaultKeys = bridgeConstants.getGenesisFederation().getBtcPublicKeys();
        List<BtcECKey> emergencyKeys = bridgeConstants.getErpFedPubKeysList();
        long activationDelay = bridgeConstants.getErpFedActivationDelay();

        ActivationConfig.ForBlock activations = mock(ActivationConfig.ForBlock.class);

        Federation p2shErpFederation = new P2shErpFederation(
            FederationTestUtils.getFederationMembersWithBtcKeys(defaultKeys),
            ZonedDateTime.parse("2017-06-10T02:30:00Z").toInstant(),
            0L,
            bridgeConstants.getBtcParams(),
            emergencyKeys,
            activationDelay,
            activations
        );

        validateP2shErpRedeemScript(
            p2shErpFederation.getRedeemScript(),
            defaultKeys,
            emergencyKeys,
            activationDelay
        );
    }

    @Test
    void getPowPegAddress_testnet_test_hop401_2() {
        BridgeConstants bridgeTestNetConstants = BridgeTestNetConstants.getInstance();

        List<BtcECKey> powpegKeys = Arrays.stream(new String[]{
            "035834d4b1e6701d3612d51b81d666d1088ff48032d79a3def02ab2d46c8f4d3fe",
            "0362634ab57dae9cb373a5d536e66a8c4f67468bbcfb063809bab643072d78a124",
            "03c5946b3fbae03a654237da863c9ed534e0878657175b132b8ca630f245df04db"
        }).map(hex -> BtcECKey.fromPublicOnly(Hex.decode(hex))).collect(Collectors.toList());
        Address expectedAddress = Address.fromBase58(
            bridgeTestNetConstants.getBtcParams(),
            "2N5nEdhxb2ZZDRjrTDrEGotx5sWtZncBkpr"
        );

        Federation p2shErpFederation = new P2shErpFederation(
            FederationTestUtils.getFederationMembersWithBtcKeys(powpegKeys),
            Instant.now(),
            0L,
            bridgeTestNetConstants.getBtcParams(),
            bridgeTestNetConstants.getErpFedPubKeysList(),
            bridgeTestNetConstants.getErpFedActivationDelay(),
            mock(ActivationConfig.ForBlock.class)
        );

        assertEquals(expectedAddress, p2shErpFederation.getAddress());

        String redeemScriptAsHex = "645221035834d4b1e6701d3612d51b81d666d1088ff48032d79a3def02ab2d46c8f4d3fe210362634ab57dae9cb373a5d536e66a8c4f67468bbcfb063809bab643072d78a1242103c5946b3fbae03a654237da863c9ed534e0878657175b132b8ca630f245df04db53ae6702d002b2755221029cecea902067992d52c38b28bf0bb2345bda9b21eca76b16a17c477a64e433012103284178e5fbcc63c54c3b38e3ef88adf2da6c526313650041b0ef955763634ebd2103b9fc46657cf72a1afa007ecf431de1cd27ff5cc8829fa625b66ca47b967e6b2453ae68";
        byte[] redeemScriptBytes = Hex.decode(redeemScriptAsHex);

        Script redeemScript = new Script(redeemScriptBytes);

        System.out.println(redeemScript);
        assertEquals(redeemScript, p2shErpFederation.getRedeemScript());

        List<BtcECKey> emergencyKeys = bridgeTestNetConstants.getErpFedPubKeysList();
        long activationDelay = bridgeTestNetConstants.getErpFedActivationDelay();

        validateP2shErpRedeemScript(
            p2shErpFederation.getRedeemScript(),
            powpegKeys,
            emergencyKeys,
            activationDelay
        );
    }

    private static class FedMemberWithSK implements Comparable<FedMemberWithSK> {
        private final FederationMember fed;
        BtcECKey fedPrivKey;

        public static FedMemberWithSK of(String seed) {
            ECKey key = ECKey.fromPrivate(HashUtil.keccak256(seed.getBytes(StandardCharsets.UTF_8)));
            return new FedMemberWithSK(
                ByteUtil.toHexString(key.getPubKey()),
                ByteUtil.toHexString(key.getPrivKeyBytes())
            );
        }

        public static List<FedMemberWithSK> listOf(String ... seeds){
            return Arrays.stream(seeds).map(FedMemberWithSK::of).sorted().collect(Collectors.toList());
        }

        public FedMemberWithSK(String publicKeyHex, String secretKeyHex) {
            byte[] publicKeyBytes = Hex.decode(publicKeyHex);
            BtcECKey btcKey = BtcECKey.fromPublicOnly(publicKeyBytes);
            ECKey rskKey = ECKey.fromPublicOnly(publicKeyBytes);
            fed = new FederationMember(btcKey, rskKey, rskKey);
            fedPrivKey = BtcECKey.fromPrivate(Hex.decode(secretKeyHex));
        }

        public FederationMember getFed() {
            return fed;
        }

        public BtcECKey getFedPrivKey() {
            return fedPrivKey;
        }

        @Override
        public int compareTo(FedMemberWithSK other) {
            return BTC_RSK_MST_PUBKEYS_COMPARATOR.compare(this.fed, other.fed);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof FedMemberWithSK)) return false;

            FedMemberWithSK that = (FedMemberWithSK) o;

            return getFed().equals(that.getFed());
        }

        @Override
        public int hashCode() {
            return getFed().hashCode();
        }

        @Override
        public String toString() {
            return "FedMemberWithSK{" +
                       "fed=" + fed +
                       ", fedPrivKey=" + fedPrivKey +
                       '}';
        }
    }

    @Test
    void testGetSignatures() {
        int[] items = {1, 2, 3};
        String[] lines = getSignaturesPermutations(0, 1, items.length / 2 + 1, items.length).split("\n");
        Arrays.stream(lines).forEach(System.out::println);
        assertEquals(3, lines.length);
    }

    private String getSignaturesPermutations(int start, int from, int until, int size) {
        String key = start + ":" + from + ":" + until;
        if(memo.containsValue(key))
            return memo.get(key);
        else {
            if (start > size / 2 + 1 || until > size){
                return "";
            } else {
                StringBuilder sb = new StringBuilder(size / 2 + 1);
                sb.append(start);
                for (int i = from; i < until; i++) {
                    sb.append(",");
                    sb.append(i);
                }
                sb.append("\n");
                memo.put(key, sb.toString());
                if (until < size){
                    return sb + getSignaturesPermutations(start, ++from, ++until, size);
                } else {
                    int new_until = size - (size / 2 - start) + 1;
                    return sb + getSignaturesPermutations(++start, ++start, new_until, size);
                }
            }
        }
    }

    @Test
    void spendFromP2sh_after_RSKIP293_testnet_using_standard_multisig() {
        BridgeConstants bridgeConstants = BridgeTestNetConstants.getInstance();
        List<FedMemberWithSK> fedMembers = FedMemberWithSK.listOf("federator1", "federator2", "federator6");

        List<FedMemberWithSK> erpFedMembers = FedMemberWithSK.listOf("erp-fed-01", "erp-fed-02", "erp-fed-03");

        ActivationConfig.ForBlock activations = mock(ActivationConfig.ForBlock.class);
        when(activations.isActive(ConsensusRule.RSKIP284)).thenReturn(true);
        when(activations.isActive(ConsensusRule.RSKIP293)).thenReturn(true);

        P2shErpFederation fed = new P2shErpFederation(
            fedMembers.stream().map(FedMemberWithSK::getFed).collect(Collectors.toList()),
            Instant.now(),
            0L,
            bridgeConstants.getBtcParams(),
            erpFedMembers.stream().map(FedMemberWithSK::getFed).map(FederationMember::getBtcPublicKey).collect(Collectors.toList()),
            bridgeConstants.getErpFedActivationDelay(),
            activations
        );

        Address expectedAddress = Address.fromBase58(
            bridgeConstants.getBtcParams(),
            "2NEfaGq4tGe6bJUxLEzGFoVyZrSrZtXRzJ7"
        );

        assertEquals(expectedAddress, fed.getAddress());

        String RAW_FUND_TX = "0200000002bdf6c06aa8a61425ba6ff7003807202a29a21d37619ddf3554fb81007343ce3f01000000fd6f0100483045022100bb5e24cbf26f9b5b6c607f6fec4cedb63055c9618d0d58bb180316bad066214a02203f9f005ed91723748a375d08a2cd68a40774894e888dab39adccc34eb869c3dd0147304402207f30e81aa72f02788089f70da42056463b9c2e690c77bbce8925361dff204b080220434649b59902372e30bc70d5e98f4bc7448936d0eb260a764ac4cb745f858fbf01004cda64522103462ab7041341dadd996dc12ef0c118ca8ccb546498cbf304f7ffe0f1b12f9a9e210362634ab57dae9cb373a5d536e66a8c4f67468bbcfb063809bab643072d78a1242103c5946b3fbae03a654237da863c9ed534e0878657175b132b8ca630f245df04db53ae6702d002b2755221029cecea902067992d52c38b28bf0bb2345bda9b21eca76b16a17c477a64e433012103284178e5fbcc63c54c3b38e3ef88adf2da6c526313650041b0ef955763634ebd2103b9fc46657cf72a1afa007ecf431de1cd27ff5cc8829fa625b66ca47b967e6b2453ae68ffffffffe6d80a4238753055e3504b3a687b412190619bab29c3005e34e0250f011d304f00000000fd6f0100483045022100fa66060405eab35ade02e481559657d2529f456510ee62005f9c9d2408655795022077fe7e3aff0488aa11509988e3c2d6330d3b75962c2531a2e13741746cd030f4014730440220399af21abd6bdb013eda0b99f3c702794249482c478cf664755a1fb1c1b3a392022075e146ab91d070993f4b63d67f58970baa425d18a9f2b413d731307e5888f66c01004cda64522103462ab7041341dadd996dc12ef0c118ca8ccb546498cbf304f7ffe0f1b12f9a9e210362634ab57dae9cb373a5d536e66a8c4f67468bbcfb063809bab643072d78a1242103c5946b3fbae03a654237da863c9ed534e0878657175b132b8ca630f245df04db53ae6702d002b2755221029cecea902067992d52c38b28bf0bb2345bda9b21eca76b16a17c477a64e433012103284178e5fbcc63c54c3b38e3ef88adf2da6c526313650041b0ef955763634ebd2103b9fc46657cf72a1afa007ecf431de1cd27ff5cc8829fa625b66ca47b967e6b2453ae68ffffffff024e070700000000001976a914cab5925c59a9a413f8d443000abcc5640bdf067588ac836408000000000017a914eaf58ece160a383630667cfc1ccff519ab07c4728700000000";
        BtcTransaction pegInTx = new BtcTransaction(bridgeConstants.getBtcParams(), Hex.decode(RAW_FUND_TX));
        int outputIndex = 1; // Remember to change this value accordingly in case of using an existing raw tx

        Address destinationAddress = Address.fromBase58(bridgeConstants.getBtcParams(), "2NEfaGq4tGe6bJUxLEzGFoVyZrSrZtXRzJ7");

        spendFromFed(
            bridgeConstants,
            bridgeConstants.getErpFedActivationDelay(),
            fed,
            fedMembers,
            false,
            pegInTx,
            outputIndex,
            destinationAddress
        );
    }

    private void spendFromFed(
        BridgeConstants  bridgeConstants,
        long activationDelay,
        Federation fed,
        List<FedMemberWithSK> signers,
        boolean signWithEmergencyMultisig,
        BtcTransaction pegInTx,
        int outputIndex,
        Address destinationAddress
    ) {
        NetworkParameters networkParameters = bridgeConstants.getBtcParams();

        BtcTransaction pegOutTx = new BtcTransaction(networkParameters);
        pegOutTx.addInput(pegInTx.getOutput(outputIndex));
        pegOutTx.addOutput(pegInTx.getOutput(outputIndex).getValue().minus(Coin.valueOf(1_000L)), destinationAddress);
        pegOutTx.setVersion(2);
        if (signWithEmergencyMultisig){
            pegOutTx.getInput(0).setSequenceNumber(activationDelay);
        }
        //

        // Create signatures
        Sha256Hash sigHash = pegOutTx.hashForSignature(
            0,
            fed.getRedeemScript(),
            BtcTransaction.SigHash.ALL,
            false
        );

        List<BtcECKey.ECDSASignature> signatures = signers.stream().map(FedMemberWithSK::getFedPrivKey).map(privateKey -> privateKey.sign(sigHash)).collect(Collectors.toList());

        String[] permutations = getSignaturesPermutations(0, 1, signatures.size() / 2 + 1, signatures.size()).split("\n");
        for (String permutation: permutations) {
            String[] idxs = permutation.split(",");
            List<BtcECKey.ECDSASignature> sub = Arrays.stream(idxs).mapToInt(Integer::parseInt).mapToObj(signatures::get).collect(Collectors.toList());

            Script inputScript = createInputScript(fed, sub, signWithEmergencyMultisig);
            pegOutTx.getInput(0).setScriptSig(inputScript);
            inputScript.correctlySpends(pegOutTx,0, pegInTx.getOutput(outputIndex).getScriptPubKey());
        }

        // Uncomment to print the raw tx in console and broadcast https://blockstream.info/testnet/tx/push
        System.out.println(Hex.toHexString(pegOutTx.bitcoinSerialize()));
    }

    private Script createInputScript(
        Federation federation,
        List<BtcECKey.ECDSASignature> signatures,
        boolean signWithTheEmergencyMultisig) {

        List<byte[]> txSignaturesEncoded = signatures.stream().map(signature -> {
            TransactionSignature txSignature1 = new TransactionSignature(
                signature,
                BtcTransaction.SigHash.ALL,
                false
            );
            return txSignature1.encodeToBitcoin();
        }).collect(Collectors.toList());

        ScriptBuilder scriptBuilder = new ScriptBuilder();
        scriptBuilder = scriptBuilder.number(0);
        txSignaturesEncoded.forEach(scriptBuilder::data);

        if (federation instanceof P2shErpFederation || federation instanceof ErpFederation){
            int flowOpCode = signWithTheEmergencyMultisig ? 1 : 0;
            scriptBuilder.number(flowOpCode);
        }
        return scriptBuilder.data(federation.getRedeemScript().getProgram()).build();
    }

    Map<String, String> memo = new HashMap<>();

    private void validateP2shErpRedeemScript(
        Script erpRedeemScript,
        List<BtcECKey> defaultMultisigKeys,
        List<BtcECKey> emergencyMultisigKeys,
        Long csvValue) {

        // Keys are sorted when added to the redeem script, so we need them sorted in order to validate
        defaultMultisigKeys.sort(BtcECKey.PUBKEY_COMPARATOR);
        emergencyMultisigKeys.sort(BtcECKey.PUBKEY_COMPARATOR);

        byte[] serializedCsvValue = Utils.signedLongToByteArrayLE(csvValue);

        byte[] script = erpRedeemScript.getProgram();
        Assertions.assertTrue(script.length > 0);

        int index = 0;

        // First byte should equal OP_NOTIF
        assertEquals(ScriptOpCodes.OP_NOTIF, script[index++]);

        // Next byte should equal M, from an M/N multisig
        int m = defaultMultisigKeys.size() / 2 + 1;
        assertEquals(ScriptOpCodes.getOpCode(String.valueOf(m)), script[index++]);

        // Assert public keys
        for (BtcECKey key: defaultMultisigKeys) {
            byte[] pubkey = key.getPubKey();
            assertEquals(pubkey.length, script[index++]);
            for (byte b : pubkey) {
                assertEquals(b, script[index++]);
            }
        }

        // Next byte should equal N, from an M/N multisig
        int n = defaultMultisigKeys.size();
        assertEquals(ScriptOpCodes.getOpCode(String.valueOf(n)), script[index++]);

        // Next byte should equal OP_CHECKMULTISIG
        assertEquals(Integer.valueOf(ScriptOpCodes.OP_CHECKMULTISIG).byteValue(), script[index++]);

        // Next byte should equal OP_ELSE
        assertEquals(ScriptOpCodes.OP_ELSE, script[index++]);

        // Next byte should equal csv value length
        assertEquals(serializedCsvValue.length, script[index++]);

        // Next bytes should equal the csv value in bytes
        for (int i = 0; i < serializedCsvValue.length; i++) {
            assertEquals(serializedCsvValue[i], script[index++]);
        }

        assertEquals(Integer.valueOf(ScriptOpCodes.OP_CHECKSEQUENCEVERIFY).byteValue(), script[index++]);
        assertEquals(ScriptOpCodes.OP_DROP, script[index++]);

        // Next byte should equal M, from an M/N multisig
        m = emergencyMultisigKeys.size() / 2 + 1;
        assertEquals(ScriptOpCodes.getOpCode(String.valueOf(m)), script[index++]);

        for (BtcECKey key: emergencyMultisigKeys) {
            byte[] pubkey = key.getPubKey();
            assertEquals(Integer.valueOf(pubkey.length).byteValue(), script[index++]);
            for (byte b : pubkey) {
                assertEquals(b, script[index++]);
            }
        }

        // Next byte should equal N, from an M/N multisig
        n = emergencyMultisigKeys.size();
        assertEquals(ScriptOpCodes.getOpCode(String.valueOf(n)), script[index++]);

        // Next byte should equal OP_CHECKMULTISIG
        assertEquals(Integer.valueOf(ScriptOpCodes.OP_CHECKMULTISIG).byteValue(), script[index++]);

        assertEquals(ScriptOpCodes.OP_ENDIF, script[index++]);
    }
}
