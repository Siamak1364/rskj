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

package org.ethereum.rpc;

import java.util.Collection;

import org.ethereum.core.Block;
import org.ethereum.core.Blockchain;
import org.ethereum.core.Bloom;
import org.ethereum.core.Transaction;
import org.ethereum.core.TransactionReceipt;
import org.ethereum.db.TransactionInfo;
import org.ethereum.rpc.exception.RskJsonRpcRequestException;
import org.ethereum.vm.LogInfo;

import co.rsk.core.RskAddress;
import co.rsk.crypto.Keccak256;
import co.rsk.logfilter.BlocksBloom;
import co.rsk.logfilter.BlocksBloomStore;
import co.rsk.util.HexUtils;

/**
 * Created by ajlopez on 17/01/2018.
 */
public class LogFilter extends Filter {
    class LogFilterEvent extends FilterEvent {
        private final LogFilterElement el;

        LogFilterEvent(LogFilterElement el) {
            this.el = el;
        }

        @Override
        public LogFilterElement getJsonEventObject() {
            return el;
        }
    }

    private AddressesTopicsFilter addressesTopicsFilter;
    private boolean fromLatestBlock;
    private boolean toLatestBlock;
    private final Blockchain blockchain;

    public LogFilter(AddressesTopicsFilter addressesTopicsFilter, Blockchain blockchain, boolean fromLatestBlock, boolean toLatestBlock) {
        this.addressesTopicsFilter = addressesTopicsFilter;
        this.blockchain = blockchain;
        this.fromLatestBlock = fromLatestBlock;
        this.toLatestBlock = toLatestBlock;
    }

    void onLogMatch(LogInfo logInfo, Block b, int txIndex, Transaction tx, int logIdx) {
        add(new LogFilterEvent(new LogFilterElement(logInfo, b, txIndex, tx, logIdx)));
    }

    void onTransaction(Transaction tx, Block b, int txIndex) {
        TransactionInfo txInfo = blockchain.getTransactionInfo(tx.getHash().getBytes());
        TransactionReceipt receipt = txInfo.getReceipt();

        LogFilterElement[] logs = new LogFilterElement[receipt.getLogInfoList().size()];

        for (int i = 0; i < logs.length; i++) {
            LogInfo logInfo = receipt.getLogInfoList().get(i);

            if (addressesTopicsFilter.matchesExactly(logInfo)) {
                onLogMatch(logInfo, b, txIndex, receipt.getTransaction(), i);
            }
        }
    }

    void onBlock(Block b) {
        if (addressesTopicsFilter.matchBloom(new Bloom(b.getLogBloom()))) {
            int txIdx = 0;

            for (Transaction tx : b.getTransactionsList()) {
                onTransaction(tx, b, txIdx);
                txIdx++;
            }
        }
    }

    @Override
    public void newBlockReceived(Block b) {
        if (this.fromLatestBlock) {
            this.clearEvents();
            onBlock(b);
        }
        else if (this.toLatestBlock) {
            onBlock(b);
        }
    }

    @Override
    public void newPendingTx(Transaction tx) {
        //empty method
    }

    public static LogFilter fromFilterRequest(FilterRequest fr, Blockchain blockchain, BlocksBloomStore blocksBloomStore) throws Exception {
        RskAddress[] addresses;

        // Now, there is an array of array of topics
        // first level are topic filters by position
        // second level contains OR topic filters for that position
        // null value matches anything
        Topic[][] topics;

        if (fr.getAddress() instanceof String) {
            addresses = new RskAddress[] { new RskAddress(HexUtils.stringHexToByteArray((String) fr.getAddress())) };
        } else if (fr.getAddress() instanceof Collection<?>) {
            Collection<?> iterable = (Collection<?>)fr.getAddress();

            addresses = iterable.stream()
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .map(HexUtils::stringHexToByteArray)
                    .map(RskAddress::new)
                    .toArray(RskAddress[]::new);
        }
        else {
            addresses = new RskAddress[0];
        }

        if (fr.getTopics() != null) {
            topics = new Topic[fr.getTopics().length][];

            for (int nt = 0; nt < fr.getTopics().length; nt++) {
                Object topic = fr.getTopics()[nt];

                if (topic == null) {
                    topics[nt] = new Topic[0];
                } else if (topic instanceof String) {
                    topics[nt] = new Topic[] { new Topic((String) topic) };
                } else if (topic instanceof Collection<?>) {
                    // TODO list of topics as topic with OR logic

                    Collection<?> iterable = (Collection<?>)topic;

                    topics[nt] = iterable.stream()
                            .filter(String.class::isInstance)
                            .map(String.class::cast)
                            .map(HexUtils::stringHexToByteArray)
                            .map(Topic::new)
                            .toArray(Topic[]::new);
                }
            }
        }
        else {
            topics = null;
        }

        AddressesTopicsFilter addressesTopicsFilter = new AddressesTopicsFilter(addresses, topics);

        // TODO review pending transaction processing
        // when fromBlock and/or toBlock are "pending"

        validateFilterRequestParameters(fr);

        // Default from block value
        if (fr.getFromBlock() == null) {
            fr.setFromBlock("latest");
        }

        // Default to block value
        if (fr.getToBlock() == null) {
            fr.setToBlock("latest");
        }

        boolean fromLatestBlock = "latest".equalsIgnoreCase(fr.getFromBlock());
        boolean toLatestBlock = "latest".equalsIgnoreCase(fr.getToBlock());

        LogFilter filter = new LogFilter(addressesTopicsFilter, blockchain, fromLatestBlock, toLatestBlock);

        retrieveHistoricalData(fr, blockchain, filter, blocksBloomStore);

        return filter;
    }

    /**
     * Cannot use both blockHash and fromBlock/toBlock filters, according to EIP-234
     */
    private static void validateFilterRequestParameters(FilterRequest fr) {
        if (fr.getBlockHash() != null && (fr.getFromBlock() != null  || fr.getToBlock() != null)) {
            throw RskJsonRpcRequestException.invalidParamError("Cannot specify both blockHash and fromBlock/toBlock");
        }
    }

    private static void retrieveHistoricalData(FilterRequest fr, Blockchain blockchain, LogFilter filter, BlocksBloomStore blocksBloomStore) {

        if (fr.getBlockHash() != null) {
            processSingleBlockByHash(fr.getBlockHash(), blockchain, filter, blocksBloomStore);
            return;
        }

        Block blockFrom = isBlockWord(fr.getFromBlock()) ? null : Web3Impl.getBlockByNumberOrStr(fr.getFromBlock(), blockchain);
        Block blockTo = isBlockWord(fr.getToBlock()) ? null : Web3Impl.getBlockByNumberOrStr(fr.getToBlock(), blockchain);

        if (blockFrom == null && "earliest".equalsIgnoreCase(fr.getFromBlock())) {
            blockFrom = blockchain.getBlockByNumber(0);
        }

        if (blockFrom != null) {
            // need to add historical data
            blockTo = blockTo == null ? blockchain.getBestBlock() : blockTo;

            processBlocks(blockFrom.getNumber(), blockTo.getNumber(), filter, blockchain, blocksBloomStore);
        }
        else if ("latest".equalsIgnoreCase(fr.getFromBlock())) {
            filter.onBlock(blockchain.getBestBlock());
        }
    }

    private static void processSingleBlockByHash(String blockHash, Blockchain blockchain, LogFilter filter, BlocksBloomStore blocksBloomStore) {
        Keccak256 keccak256BlockHash = new Keccak256(HexUtils.stringHexToByteArray(blockHash));
        Block blockByHash = blockchain.getBlockByHash(keccak256BlockHash.getBytes());
        if (blockByHash == null) {
            return;
        }

        long blockNumber = blockByHash.getNumber();
        processBlocks(blockNumber, blockNumber, filter, blockchain, blocksBloomStore);
    }

    private static void processBlocks(long fromBlockNumber, long toBlockNumber, LogFilter filter, Blockchain blockchain, BlocksBloomStore blocksBloomStore) {
        BlocksBloom auxiliaryBlocksBloom = null;
        long bestBlockNumber = blockchain.getBestBlock().getNumber();

        for (long blockNum = fromBlockNumber; blockNum <= toBlockNumber; blockNum++) {
            if (Thread.interrupted()) {
                return; // TODO log sth maybe
            }

            boolean isConfirmedBlock = blockNum <= bestBlockNumber - blocksBloomStore.getNoConfirmations();

            if (isConfirmedBlock) {
                if (blocksBloomStore.firstNumberInRange(blockNum) == blockNum) {
                    if (blocksBloomStore.hasBlockNumber(blockNum)) {
                        BlocksBloom blocksBloom = blocksBloomStore.getBlocksBloomByNumber(blockNum);

                        if (!filter.addressesTopicsFilter.matchBloom(blocksBloom.getBloom())) {
                            blockNum = blocksBloomStore.lastNumberInRange(blockNum);
                            continue;
                        }
                    }

                    auxiliaryBlocksBloom = new BlocksBloom();
                }

                Block block = blockchain.getBlockByNumber(blockNum);

                if (auxiliaryBlocksBloom != null) {
                    auxiliaryBlocksBloom.addBlockBloom(blockNum, new Bloom(block.getLogBloom()));
                }

                if (auxiliaryBlocksBloom != null && blocksBloomStore.lastNumberInRange(blockNum) == blockNum) {
                    blocksBloomStore.addBlocksBloom(auxiliaryBlocksBloom);
                }

                filter.onBlock(block);
            }
            else {
                filter.onBlock(blockchain.getBlockByNumber(blockNum));
            }
        }
    }

    private static boolean isBlockWord(String id) {
        return "latest".equalsIgnoreCase(id) || "pending".equalsIgnoreCase(id) || "earliest".equalsIgnoreCase(id);
    }
}
