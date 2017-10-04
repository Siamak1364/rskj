package co.rsk.net.utils;

import co.rsk.net.sync.SyncPeerProcessor;

public final class SyncUtils {
    public static int syncSetupRequests(long bestBlock, long currentBestBlock) {
        if (currentBestBlock >= bestBlock) {
            return 1;
        }

        // 192 and 5 are configuration values that are hardcoded for testing
        // 192: chunk size
        // 5: max chunks to download in skeleton
        int skippedChunks = (int) Math.floor(currentBestBlock / 192f);
        int chunksToBestBlock = (int) Math.ceil(bestBlock / 192f);
        int chunksToDownload = Math.max(1, Math.min(5, chunksToBestBlock - skippedChunks));
        return 1 + // get status
                binarySearchExpectedRequests(bestBlock, currentBestBlock) + // find connection point
                1 + // get skeleton
                chunksToDownload; // get headers chunks
    }

    private static int binarySearchExpectedRequests(long bestBlock, long currentBestBlock) {
        SyncPeerProcessor syncPeerProcessor = new SyncPeerProcessor();
        syncPeerProcessor.startFindConnectionPoint(bestBlock);
        int i = 0;
        while (!syncPeerProcessor.getConnectionPoint().isPresent()) {
            i++;
            if (syncPeerProcessor.getFindingHeight() <= currentBestBlock)
                syncPeerProcessor.updateFound();
            else
                syncPeerProcessor.updateNotFound();
        }

        return i;
    }
}
