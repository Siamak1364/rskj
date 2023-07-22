/*
 * This file is part of RskJ
 * Copyright (C) 2023 RSK Labs Ltd.
 * (derived from ethereumJ library, Copyright (c) 2016 <ether.camp>)
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
package org.ethereum.rpc.validation;

import co.rsk.util.HexUtils;
import org.ethereum.rpc.exception.RskJsonRpcRequestException;

public class BlockHashValidator {
    private static int BLOCK_HASH_BYTE_LENGTH = 32;
    private BlockHashValidator() {

    }

    public static boolean isValid(String blockHash) {
        byte[] blockHashBytes;

        try {
            blockHashBytes = HexUtils.stringHexToByteArray(blockHash);
        } catch (Exception e) {
            throw RskJsonRpcRequestException.invalidParamError("Invalid block hash format. " + e.getMessage());
        }

        if (BLOCK_HASH_BYTE_LENGTH != blockHashBytes.length) {
            throw RskJsonRpcRequestException.invalidParamError("Invalid block hash: incorrect length.");
        }

        return true;
    }
}
