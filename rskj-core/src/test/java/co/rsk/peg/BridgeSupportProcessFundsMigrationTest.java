package co.rsk.peg;

import co.rsk.bitcoinj.core.BtcTransaction;
import co.rsk.bitcoinj.core.Coin;
import co.rsk.bitcoinj.core.UTXO;
import co.rsk.blockchain.utils.BlockGenerator;
import co.rsk.config.BridgeConstants;
import co.rsk.config.BridgeMainNetConstants;
import co.rsk.config.BridgeTestNetConstants;
import co.rsk.peg.utils.BridgeEventLogger;
import co.rsk.test.builders.BridgeSupportBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.ethereum.config.Constants;
import org.ethereum.config.blockchain.upgrades.ActivationConfig;
import org.ethereum.config.blockchain.upgrades.ConsensusRule;
import org.ethereum.core.Transaction;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.math.BigInteger;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Stream;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class BridgeSupportProcessFundsMigrationTest {

    @Test
    void processFundsMigration_in_migration_age_before_rskip_146_activation_testnet() throws IOException {
        ActivationConfig.ForBlock activations = mock(ActivationConfig.ForBlock.class);
        when(activations.isActive(ConsensusRule.RSKIP146)).thenReturn(false);
        when(activations.isActive(ConsensusRule.RSKIP357)).thenReturn(false);
        when(activations.isActive(ConsensusRule.RSKIP374)).thenReturn(false);
        test_processFundsMigration(BridgeTestNetConstants.getInstance(), activations, true);
    }

    @Test
    void processFundsMigration_in_migration_age_after_rskip_146_activation_testnet() throws IOException {
        ActivationConfig.ForBlock activations = mock(ActivationConfig.ForBlock.class);
        when(activations.isActive(ConsensusRule.RSKIP146)).thenReturn(true);
        when(activations.isActive(ConsensusRule.RSKIP357)).thenReturn(false);
        when(activations.isActive(ConsensusRule.RSKIP374)).thenReturn(false);
        test_processFundsMigration(BridgeTestNetConstants.getInstance(), activations, true);
    }

    @Test
    void processFundsMigration_in_migration_age_after_rskip_357_activation_testnet() throws IOException {
        ActivationConfig.ForBlock activations = mock(ActivationConfig.ForBlock.class);
        when(activations.isActive(ConsensusRule.RSKIP146)).thenReturn(true);
        when(activations.isActive(ConsensusRule.RSKIP357)).thenReturn(true);
        when(activations.isActive(ConsensusRule.RSKIP374)).thenReturn(false);
        test_processFundsMigration(BridgeTestNetConstants.getInstance(), activations, true);
    }

    @Test
    void processFundsMigration_in_migration_age_after_rskip_374_activation_testnet() throws IOException {
        ActivationConfig.ForBlock activations = mock(ActivationConfig.ForBlock.class);
        when(activations.isActive(ConsensusRule.RSKIP146)).thenReturn(true);
        when(activations.isActive(ConsensusRule.RSKIP357)).thenReturn(true);
        when(activations.isActive(ConsensusRule.RSKIP374)).thenReturn(true);
        test_processFundsMigration(BridgeTestNetConstants.getInstance(), activations, true);
    }

    @Test
    void processFundsMigration_in_migration_age_after_rskip383_activation_testnet() throws IOException {
        ActivationConfig.ForBlock activations = mock(ActivationConfig.ForBlock.class);
        when(activations.isActive(ConsensusRule.RSKIP146)).thenReturn(true);
        when(activations.isActive(ConsensusRule.RSKIP357)).thenReturn(true);
        when(activations.isActive(ConsensusRule.RSKIP374)).thenReturn(true);
        when(activations.isActive(ConsensusRule.RSKIP383)).thenReturn(true);
        test_processFundsMigration(BridgeMainNetConstants.getInstance(), activations, true);
    }

    @Test
    void processFundsMigration_past_migration_age_before_rskip_146_activation_testnet() throws IOException {
        ActivationConfig.ForBlock activations = mock(ActivationConfig.ForBlock.class);
        when(activations.isActive(ConsensusRule.RSKIP146)).thenReturn(false);
        when(activations.isActive(ConsensusRule.RSKIP357)).thenReturn(false);
        when(activations.isActive(ConsensusRule.RSKIP374)).thenReturn(false);
        test_processFundsMigration(BridgeTestNetConstants.getInstance(), activations, false);
    }

    @Test
    void processFundsMigration_past_migration_age_after_rskip_146_activation_testnet() throws IOException {
        ActivationConfig.ForBlock activations = mock(ActivationConfig.ForBlock.class);
        when(activations.isActive(ConsensusRule.RSKIP146)).thenReturn(true);
        when(activations.isActive(ConsensusRule.RSKIP357)).thenReturn(false);
        when(activations.isActive(ConsensusRule.RSKIP374)).thenReturn(false);
        test_processFundsMigration(BridgeTestNetConstants.getInstance(), activations, false);
    }

    @Test
    void processFundsMigration_past_migration_age_after_rskip_357_activation_testnet() throws IOException {
        ActivationConfig.ForBlock activations = mock(ActivationConfig.ForBlock.class);
        when(activations.isActive(ConsensusRule.RSKIP146)).thenReturn(true);
        when(activations.isActive(ConsensusRule.RSKIP357)).thenReturn(true);
        when(activations.isActive(ConsensusRule.RSKIP374)).thenReturn(false);
        test_processFundsMigration(BridgeTestNetConstants.getInstance(), activations, false);
    }

    @Test
    void processFundsMigration_past_migration_age_after_rskip_374_activation_testnet() throws IOException {
        ActivationConfig.ForBlock activations = mock(ActivationConfig.ForBlock.class);
        when(activations.isActive(ConsensusRule.RSKIP146)).thenReturn(true);
        when(activations.isActive(ConsensusRule.RSKIP357)).thenReturn(true);
        when(activations.isActive(ConsensusRule.RSKIP374)).thenReturn(true);
        test_processFundsMigration(BridgeTestNetConstants.getInstance(), activations, false);
    }

    @Test
    void processFundsMigration_past_migration_age_after_rskip383_activation_testnet() throws IOException {
        ActivationConfig.ForBlock activations = mock(ActivationConfig.ForBlock.class);
        when(activations.isActive(ConsensusRule.RSKIP146)).thenReturn(true);
        when(activations.isActive(ConsensusRule.RSKIP357)).thenReturn(true);
        when(activations.isActive(ConsensusRule.RSKIP374)).thenReturn(true);
        when(activations.isActive(ConsensusRule.RSKIP383)).thenReturn(true);
        test_processFundsMigration(BridgeTestNetConstants.getInstance(), activations, false);
    }

    @Test
    void processFundsMigration_in_migration_age_before_rskip_146_activation_mainnet() throws IOException {
        ActivationConfig.ForBlock activations = mock(ActivationConfig.ForBlock.class);
        when(activations.isActive(ConsensusRule.RSKIP146)).thenReturn(false);
        when(activations.isActive(ConsensusRule.RSKIP357)).thenReturn(false);
        when(activations.isActive(ConsensusRule.RSKIP374)).thenReturn(false);
        test_processFundsMigration(BridgeMainNetConstants.getInstance(), activations, true);
    }

    @Test
    void processFundsMigration_in_migration_age_after_rskip_146_activation_mainnet() throws IOException {
        ActivationConfig.ForBlock activations = mock(ActivationConfig.ForBlock.class);
        when(activations.isActive(ConsensusRule.RSKIP146)).thenReturn(true);
        when(activations.isActive(ConsensusRule.RSKIP357)).thenReturn(false);
        when(activations.isActive(ConsensusRule.RSKIP374)).thenReturn(false);
        test_processFundsMigration(BridgeMainNetConstants.getInstance(), activations, true);
    }

    @Test
    void processFundsMigration_in_migration_age_after_rskip_357_activation_mainnet() throws IOException {
        ActivationConfig.ForBlock activations = mock(ActivationConfig.ForBlock.class);
        when(activations.isActive(ConsensusRule.RSKIP146)).thenReturn(true);
        when(activations.isActive(ConsensusRule.RSKIP357)).thenReturn(true);
        when(activations.isActive(ConsensusRule.RSKIP374)).thenReturn(false);
        test_processFundsMigration(BridgeMainNetConstants.getInstance(), activations, true);
    }

    @Test
    void processFundsMigration_in_migration_age_after_rskip_374_activation_mainnet() throws IOException {
        ActivationConfig.ForBlock activations = mock(ActivationConfig.ForBlock.class);
        when(activations.isActive(ConsensusRule.RSKIP146)).thenReturn(true);
        when(activations.isActive(ConsensusRule.RSKIP357)).thenReturn(true);
        when(activations.isActive(ConsensusRule.RSKIP374)).thenReturn(true);
        test_processFundsMigration(BridgeMainNetConstants.getInstance(), activations, true);
    }

    @Test
    void processFundsMigration_in_migration_age_after_rskip383_activation_mainnet() throws IOException {
        ActivationConfig.ForBlock activations = mock(ActivationConfig.ForBlock.class);
        when(activations.isActive(ConsensusRule.RSKIP146)).thenReturn(true);
        when(activations.isActive(ConsensusRule.RSKIP357)).thenReturn(true);
        when(activations.isActive(ConsensusRule.RSKIP374)).thenReturn(true);
        when(activations.isActive(ConsensusRule.RSKIP383)).thenReturn(true);
        test_processFundsMigration(BridgeMainNetConstants.getInstance(), activations, true);
    }

    @Test
    void processFundsMigration_past_migration_age_before_rskip_146_activation_mainnet() throws IOException {
        ActivationConfig.ForBlock activations = mock(ActivationConfig.ForBlock.class);
        when(activations.isActive(ConsensusRule.RSKIP146)).thenReturn(false);
        when(activations.isActive(ConsensusRule.RSKIP357)).thenReturn(false);
        when(activations.isActive(ConsensusRule.RSKIP374)).thenReturn(false);
        test_processFundsMigration(BridgeMainNetConstants.getInstance(), activations, false);
    }

    @Test
    void processFundsMigration_past_migration_age_after_rskip_146_activation_mainnet() throws IOException {
        ActivationConfig.ForBlock activations = mock(ActivationConfig.ForBlock.class);
        when(activations.isActive(ConsensusRule.RSKIP146)).thenReturn(true);
        when(activations.isActive(ConsensusRule.RSKIP357)).thenReturn(false);
        when(activations.isActive(ConsensusRule.RSKIP374)).thenReturn(false);
        test_processFundsMigration(BridgeMainNetConstants.getInstance(), activations, false);
    }

    @Test
    void processFundsMigration_past_migration_age_after_rskip_357_activation_mainnet() throws IOException {
        ActivationConfig.ForBlock activations = mock(ActivationConfig.ForBlock.class);
        when(activations.isActive(ConsensusRule.RSKIP146)).thenReturn(true);
        when(activations.isActive(ConsensusRule.RSKIP357)).thenReturn(true);
        when(activations.isActive(ConsensusRule.RSKIP374)).thenReturn(false);
        test_processFundsMigration(BridgeMainNetConstants.getInstance(), activations, false);
    }

    @Test
    void processFundsMigration_past_migration_age_after_rskip_374_activation_mainnet() throws IOException {
        ActivationConfig.ForBlock activations = mock(ActivationConfig.ForBlock.class);
        when(activations.isActive(ConsensusRule.RSKIP146)).thenReturn(true);
        when(activations.isActive(ConsensusRule.RSKIP357)).thenReturn(true);
        when(activations.isActive(ConsensusRule.RSKIP374)).thenReturn(true);
        test_processFundsMigration(BridgeMainNetConstants.getInstance(), activations, false);
    }

    @Test
    void processFundsMigration_past_migration_age_after_rskip383_activation_mainnet() throws IOException {
        ActivationConfig.ForBlock activations = mock(ActivationConfig.ForBlock.class);
        when(activations.isActive(ConsensusRule.RSKIP146)).thenReturn(true);
        when(activations.isActive(ConsensusRule.RSKIP357)).thenReturn(true);
        when(activations.isActive(ConsensusRule.RSKIP374)).thenReturn(true);
        when(activations.isActive(ConsensusRule.RSKIP383)).thenReturn(true);
        test_processFundsMigration(BridgeMainNetConstants.getInstance(), activations, false);
    }

    private static Stream<Arguments> processFundMigrationArgsProvider() {
        BridgeMainNetConstants bridgeMainNetConstants = BridgeMainNetConstants.getInstance();
        BridgeTestNetConstants bridgeTestNetConstants = BridgeTestNetConstants.getInstance();

        ActivationConfig.ForBlock activationsBeforeRSKIP146 = mock(ActivationConfig.ForBlock.class);

        Stream<Arguments> beforeRskip146Tests = Stream.of(
            Arguments.of(bridgeTestNetConstants, activationsBeforeRSKIP146, false),
            Arguments.of(bridgeTestNetConstants, activationsBeforeRSKIP146, true),
            Arguments.of(bridgeMainNetConstants, activationsBeforeRSKIP146, false),
            Arguments.of(bridgeMainNetConstants, activationsBeforeRSKIP146, true)
        );

        ActivationConfig.ForBlock activationsAfterRSKIP146 = mock(ActivationConfig.ForBlock.class);
        when(activationsAfterRSKIP146.isActive(ConsensusRule.RSKIP146)).thenReturn(true);

        Stream<Arguments> afterRskip146Tests = Stream.of(
            Arguments.of(bridgeTestNetConstants, activationsAfterRSKIP146, false),
            Arguments.of(bridgeTestNetConstants, activationsAfterRSKIP146, true),
            Arguments.of(bridgeMainNetConstants, activationsAfterRSKIP146, false),
            Arguments.of(bridgeMainNetConstants, activationsAfterRSKIP146, true)
        );

        ActivationConfig.ForBlock activationsAfterRSKIP357 = mock(ActivationConfig.ForBlock.class);
        when(activationsAfterRSKIP357.isActive(ConsensusRule.RSKIP146)).thenReturn(true);
        when(activationsAfterRSKIP357.isActive(ConsensusRule.RSKIP357)).thenReturn(true);

        Stream<Arguments> afterRskip357Tests = Stream.of(
            Arguments.of(bridgeTestNetConstants, activationsAfterRSKIP357, false),
            Arguments.of(bridgeTestNetConstants, activationsAfterRSKIP357, true),
            Arguments.of(bridgeMainNetConstants, activationsAfterRSKIP357, false),
            Arguments.of(bridgeMainNetConstants, activationsAfterRSKIP357, true)
        );

        ActivationConfig.ForBlock activationsAfterRSKIP374 = mock(ActivationConfig.ForBlock.class);
        when(activationsAfterRSKIP374.isActive(ConsensusRule.RSKIP146)).thenReturn(true);
        when(activationsAfterRSKIP374.isActive(ConsensusRule.RSKIP357)).thenReturn(true);
        when(activationsAfterRSKIP374.isActive(ConsensusRule.RSKIP374)).thenReturn(true);

        Stream<Arguments> afterRskip374Tests = Stream.of(
            Arguments.of(bridgeTestNetConstants, activationsAfterRSKIP374, false),
            Arguments.of(bridgeTestNetConstants, activationsAfterRSKIP374, true),
            Arguments.of(bridgeMainNetConstants, activationsAfterRSKIP374, false),
            Arguments.of(bridgeMainNetConstants, activationsAfterRSKIP374, true)
        );

        ActivationConfig.ForBlock activationsAfterRSKIP383 = mock(ActivationConfig.ForBlock.class);
        when(activationsAfterRSKIP383.isActive(ConsensusRule.RSKIP146)).thenReturn(true);
        when(activationsAfterRSKIP383.isActive(ConsensusRule.RSKIP357)).thenReturn(true);
        when(activationsAfterRSKIP383.isActive(ConsensusRule.RSKIP374)).thenReturn(true);
        when(activationsAfterRSKIP383.isActive(ConsensusRule.RSKIP383)).thenReturn(true);

        Stream<Arguments> afterRskip383Tests = Stream.of(
            Arguments.of(bridgeTestNetConstants, activationsAfterRSKIP383, false),
            Arguments.of(bridgeTestNetConstants, activationsAfterRSKIP383, true),
            Arguments.of(bridgeMainNetConstants, activationsAfterRSKIP383, false),
            Arguments.of(bridgeMainNetConstants, activationsAfterRSKIP383, true)
        );
        return Stream.of(
            beforeRskip146Tests,
            afterRskip146Tests,
            afterRskip357Tests,
            afterRskip374Tests,
            afterRskip383Tests
        ).flatMap(Function.identity());
    }

    @ParameterizedTest
    @MethodSource("processFundMigrationArgsProvider")
    void test_processFundsMigration(
        BridgeConstants bridgeConstants,
        ActivationConfig.ForBlock activations,
        boolean inMigrationAge
    ) throws IOException {
        BridgeEventLogger bridgeEventLogger = mock(BridgeEventLogger.class);

        Federation oldFederation = bridgeConstants.getGenesisFederation();
        long federationActivationAge = bridgeConstants.getFederationActivationAge(activations);

        long federationCreationBlockNumber = 5L;
        long federationInMigrationAgeHeight = federationCreationBlockNumber + federationActivationAge +
            bridgeConstants.getFundsMigrationAgeSinceActivationBegin() + 1;
        long federationPastMigrationAgeHeight = federationCreationBlockNumber +
            federationActivationAge +
            bridgeConstants.getFundsMigrationAgeSinceActivationEnd(activations) + 1;

        Federation newFederation = new Federation(
            FederationTestUtils.getFederationMembers(1),
            Instant.EPOCH,
            federationCreationBlockNumber,
            bridgeConstants.getBtcParams()
        );

        BridgeStorageProvider provider = mock(BridgeStorageProvider.class);
        when(provider.getReleaseRequestQueue()).thenReturn(new ReleaseRequestQueue(Collections.emptyList()));
        when(provider.getPegoutsWaitingForConfirmations()).thenReturn(new PegoutsWaitingForConfirmations(Collections.emptySet()));
        when(provider.getOldFederation()).thenReturn(oldFederation);
        when(provider.getNewFederation()).thenReturn(newFederation);

        BlockGenerator blockGenerator = new BlockGenerator();

        long updateCollectionsCallHeight = inMigrationAge ? federationInMigrationAgeHeight : federationPastMigrationAgeHeight;
        org.ethereum.core.Block rskCurrentBlock = blockGenerator.createBlock(updateCollectionsCallHeight, 1);

        BridgeSupport bridgeSupport = new BridgeSupportBuilder()
            .withBridgeConstants(bridgeConstants)
            .withProvider(provider)
            .withEventLogger(bridgeEventLogger)
            .withExecutionBlock(rskCurrentBlock)
            .withActivations(activations)
            .build();

        List<UTXO> sufficientUTXOsForMigration = new ArrayList<>();
        sufficientUTXOsForMigration.add(PegTestUtils.createUTXO(
            0,
            0,
            Coin.COIN,
            oldFederation.getAddress()
        ));
        when(provider.getOldFederationBtcUTXOs()).thenReturn(sufficientUTXOsForMigration);

        Transaction updateCollectionsTx = buildUpdateCollectionsTransaction();
        bridgeSupport.updateCollections(updateCollectionsTx);

        Assertions.assertEquals(activations.isActive(ConsensusRule.RSKIP146)? 0 : 1, provider.getPegoutsWaitingForConfirmations().getEntriesWithoutHash().size());
        Assertions.assertEquals(activations.isActive(ConsensusRule.RSKIP146) ? 1 : 0, provider.getPegoutsWaitingForConfirmations().getEntriesWithHash().size());

        Assertions.assertTrue(sufficientUTXOsForMigration.isEmpty());
        if (!inMigrationAge){
            verify(provider, times(1)).setOldFederation(null);
        } else {
            verify(provider, never()).setOldFederation(null);
        }

        if (activations.isActive(ConsensusRule.RSKIP146)) {
            // Should have been logged with the migrated UTXO
            PegoutsWaitingForConfirmations.Entry entry = (PegoutsWaitingForConfirmations.Entry) provider.getPegoutsWaitingForConfirmations()
                .getEntriesWithHash()
                .toArray()[0];
            verify(bridgeEventLogger, times(1)).logReleaseBtcRequested(
                updateCollectionsTx.getHash().getBytes(),
                entry.getBtcTransaction(),
                Coin.COIN
            );
        } else {
            verify(bridgeEventLogger, never()).logReleaseBtcRequested(
                any(byte[].class),
                any(BtcTransaction.class),
                any(Coin.class)
            );
        }
    }

    private Transaction buildUpdateCollectionsTransaction() {
        final String TO_ADDRESS = "0000000000000000000000000000000000000006";
        final BigInteger DUST_AMOUNT = new BigInteger("1");
        final BigInteger NONCE = new BigInteger("0");
        final BigInteger GAS_PRICE = new BigInteger("100");
        final BigInteger GAS_LIMIT = new BigInteger("1000");
        final String DATA = "80af2871";

        return Transaction
            .builder()
            .nonce(NONCE)
            .gasPrice(GAS_PRICE)
            .gasLimit(GAS_LIMIT)
            .destination(Hex.decode(TO_ADDRESS))
            .data(Hex.decode(DATA))
            .chainId(Constants.REGTEST_CHAIN_ID)
            .value(DUST_AMOUNT)
            .build();
    }
}
