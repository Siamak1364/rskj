package co.rsk.net.messages;

import org.ethereum.util.RLP;

import java.math.BigInteger;

public class StateChunkRequestMessage extends MessageWithId {

    private final long id;
    private final long from;
    private final long blockNumber;

    public StateChunkRequestMessage(long id, long blockNumber, long from) {
        this.id = id;
        this.from = from;
        this.blockNumber = blockNumber;
    }

    @Override
    public MessageType getMessageType() {
        return MessageType.STATE_CHUNK_REQUEST_MESSAGE;
    }

    @Override
    public void accept(MessageVisitor v) {
        v.apply(this);
    }

    @Override
    public long getId() {
        return this.id;
    }

    @Override
    protected byte[] getEncodedMessageWithoutId() {
        byte[] rlpBlockNumber = RLP.encodeBigInteger(BigInteger.valueOf(this.blockNumber));
        byte[] rlpFrom = RLP.encodeBigInteger(BigInteger.valueOf(this.from));
        return RLP.encodeList(rlpBlockNumber, rlpFrom);
    }

    public long getFrom() {
        return from;
    }

    public long getBlockNumber() {
        return blockNumber;
    }
}
