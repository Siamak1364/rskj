/*
 * This file is part of RskJ
 * Copyright (C) 2018 RSK Labs Ltd.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package co.rsk.remasc;

import co.rsk.config.BridgeConstants;
import co.rsk.core.RskAddress;
import co.rsk.peg.BridgeStorageProvider;
import co.rsk.peg.FederationSupport;
import org.ethereum.config.blockchain.upgrades.ActivationConfig;
import org.ethereum.core.Block;
import org.ethereum.core.Repository;
import org.ethereum.crypto.ECKey;
import org.ethereum.vm.PrecompiledContracts;

/**
 * Created by ajlopez on 14/11/2017.
 */
public class RemascFederationProvider {
    private final FederationSupport federationSupport;

    public RemascFederationProvider(
            ActivationConfig activationConfig,
            BridgeConstants bridgeConstants,
            Repository repository,
            Block processingBlock) {

        ActivationConfig.ForBlock activations = activationConfig.forBlock(processingBlock.getNumber());
        BridgeStorageProvider bridgeStorageProvider = new BridgeStorageProvider(
                repository,
                PrecompiledContracts.BRIDGE_ADDR,
                bridgeConstants,
                activations
        );
        this.federationSupport = new FederationSupport(bridgeConstants, bridgeStorageProvider, processingBlock, activations);
    }

    public int getFederationSize() {
        return this.federationSupport.getFederationSize();
    }

    public RskAddress getFederatorAddress(int n) {
        byte[] publicKey = this.federationSupport.getFederatorBtcPublicKey(n);
        return new RskAddress(ECKey.fromPublicOnly(publicKey).getAddress());
    }
}
