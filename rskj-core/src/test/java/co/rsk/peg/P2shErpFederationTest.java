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

    private static class FedUtxo {
        private final BtcTransaction btcTransaction;
        private final int outputIdx;

        public static FedUtxo of(NetworkParameters networkParameters, String rawTxHex, int outputIdx){
            BtcTransaction utxo = new BtcTransaction(networkParameters, Hex.decode(rawTxHex));
            return new FedUtxo(utxo, outputIdx);
        }

        public static FedUtxo of(BtcTransaction utxo, int outputIdx){
            return new FedUtxo(utxo, outputIdx);
        }

        public FedUtxo(BtcTransaction btcTransaction, int outputIdx) {
            this.btcTransaction = btcTransaction;
            this.outputIdx = outputIdx;
        }

        public BtcTransaction getBtcTransaction() {
            return btcTransaction;
        }

        public int getOutputIdx() {
            return outputIdx;
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

        String RAW_FUND_TX = "0200000000010134ed7734da14ecde305347153f70be45021e8e29137205a9899630f56c68d3890100000000fdffffff02891300000000000017a914eaf58ece160a383630667cfc1ccff519ab07c472873c3e020000000000160014f885b26136ad4d61247132271795cc29ae9cec0302473044022063986423838cdd2abc51b150f11a1c399dce53f68f1bd02e4ec793db2fa3485c022007d8909a83b01c57dcee7e55f3989af949756c6b5068948b888622d2e6673ed70121028f117bfbc90d934b73d0d55afe54ee33a288cdde572bd3d006cede67f4c797a2e7262500";
        FedUtxo utxo1 = FedUtxo.of(new BtcTransaction(bridgeConstants.getBtcParams(), Hex.decode(RAW_FUND_TX)), 0);

        String RAW_FUND_TX2 = "020000000001013a43f0d972f5045b443c9c071bd2254f91d5b14d0b5ab5cdeab014c0ff2cc17f0200000000fdffffff027d6408000000000017a914eaf58ece160a383630667cfc1ccff519ab07c472870555dc0500000000220020617a81e635a62aa61d20fd4be369d285da2750c871016282c05a29181552d52b0400473044022048386d4e0270b68a17d3ea10d8c569c2150cb46416c82b3289f2e0ec1fe0272a02204f077bdc8f71d824a4a8a447708cb974e21c015021b94f8226a3da955024371e0147304402204fda66a5cc3503acd325671216f5dbfe4d329499321af508c4959e89072dc47802204531cb9a52c80ede1cab8ca40324ef18ddfb589a0b76f741764334f6f1e9570f014752210203307a637032952b21371f966838e03a768220f8bb663cbc2aa6d41dc71f6bbf2103fdadd0c267fc7a4890c37c6730ca124d53ad7001ee6d9ad00ed50b52a46d784552aee7262500";
        FedUtxo utxo2 = FedUtxo.of(new BtcTransaction(bridgeConstants.getBtcParams(), Hex.decode(RAW_FUND_TX2)), 0);

        String RAW_FUND_TX3 = "020000000001016a040fa1ec01bac865d4802083a435fef32052091d6d7bd02cc784d00d75e8400100000000fdffffff02916408000000000017a914eaf58ece160a383630667cfc1ccff519ab07c47287beefd305000000002200201ca17d3f37320ac4469faa1119824d98bbec3b1a586174901834d2b842715e7c0400473044022044033baafc0c15c8e2c3128d01f29a7c7c5c6ec790ead8c5be2610efb0e9d581022014b605cb59a5254a189a9fcd35ec94e6f4faae18f7011a41ac7663df33fbfdc50147304402206fc734a5db737ecb37056491881da15c2f8f2ca2bb9e47db7396029b9a0ad5e102206cae6f8766679c666cfa256e886e2816882623167e92fd9e272fd9712aa49d9a0147522102b9bb9ea5c5c0a56421bc7720e81e7f3e5fb9dfcbca946f01d868940efaa5da18210309eb318fe76a6b139d70e4037dd87733ced9e3ed6f851301a88938c7033d473b52ae05272500";
        FedUtxo utxo3 = FedUtxo.of(new BtcTransaction(bridgeConstants.getBtcParams(), Hex.decode(RAW_FUND_TX3)), 0);

        String RAW_FUND_TX4 = "0200000001a223ad7e9d4f5067a8fdddf9e4137af49d5a6dad7ea952533f701061fefd010f020000006a473044022003d999e14be1e2ea15cb16df81e14b30f26c684bcbf6fcbd07975d8648e5f04402207e99a414a0ebf1c3617944610de5ea002439a1ac56e667a60c095184c2419559012102c6bf1e099ec95510a8da3d1c67026cb65a019bad57dc2255dd56a426c629327bfdffffff0300000000000000001b6a1952534b540162db6c4b118d7259c23692b162829e6bd5e4d5b0891300000000000017a914eaf58ece160a383630667cfc1ccff519ab07c4728791200000000000001976a9145952b24450e80668e069b8152a3a38ea7f6ad44c88ace7262500";
        FedUtxo utxo4 = FedUtxo.of(new BtcTransaction(bridgeConstants.getBtcParams(), Hex.decode(RAW_FUND_TX4)), 1);

        List<FedUtxo> utxos = Arrays.asList(utxo1, utxo2, utxo3, utxo4);

        Address destinationAddress = Address.fromBase58(bridgeConstants.getBtcParams(), "2MtYSUzFWEQV62r92bsGX8ewE5Mgpv4xn9M");

        spendFromFed(
            bridgeConstants,
            bridgeConstants.getErpFedActivationDelay(),
            fed,
            fedMembers,
            false,
            utxos,
            //Coin.valueOf(1_109_748L-550_013L),
            Coin.valueOf(1_107_748L),
            destinationAddress
        );
    }

    private void spendFromFed(
        BridgeConstants  bridgeConstants,
        long activationDelay,
        Federation fed,
        List<FedMemberWithSK> signers,
        boolean signWithEmergencyMultisig,
        List<FedUtxo> utxos,
        Coin amount,
        Address destinationAddress
    ) {
        NetworkParameters networkParameters = bridgeConstants.getBtcParams();

        BtcTransaction pegOutTx = new BtcTransaction(networkParameters);
        for (FedUtxo utxo: utxos) {
            pegOutTx.addInput(utxo.btcTransaction.getOutput(utxo.outputIdx));
        }
        pegOutTx.addOutput(amount, destinationAddress);
        pegOutTx.setVersion(2);
        if (signWithEmergencyMultisig){
            pegOutTx.getInput(0).setSequenceNumber(activationDelay);
        }

        for (int i = 0; i < utxos.size(); i++) {
            // Create signatures
            Sha256Hash sigHash = pegOutTx.hashForSignature(
                i,
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
                FedUtxo utxo = utxos.get(i);
                pegOutTx.getInput(i).setScriptSig(inputScript);
                inputScript.correctlySpends(pegOutTx, i, utxo.getBtcTransaction().getOutput(utxo.outputIdx).getScriptPubKey());
            }
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
