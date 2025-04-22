# Running the Python Scripts for Timelocked P2SH Transactions

This guide explains how to execute the Python scripts for creating and spending timelocked P2SH addresses, based on the steps outlined in the `e2e_execution.sh` file.  
Alternatively, you could directly execute the `./e2e_execution.sh` file. It will execute the following steps.

## Prerequisites

1. **Bitcoin Core Setup**:
   - Ensure Bitcoin Core is installed and configured for `regtest` mode.
   - Start the `bitcoind` daemon in `regtest` mode.

2. **Python Environment**:
   - Use Python 3.10.16.
   - Install the required dependencies listed in `requirements.txt`:
     ```sh
     pip install -r requirements.txt
     ```

3. **Activate Environment**:
   - Activate the Python environment where the dependencies are installed.

4. **Reset Regtest Directory** (Optional):
   - Delete the `~/.bitcoin/regtest` directory to reset the blockchain state.

5. `~/.bitcoin/bitcoin.conf` contains:
```
regtest=1
server=1
deprecatedrpc=create_bdb # this one is going to be deprecated soon-ish

[regtest]
maxtxfee=0.01
fallbackfee=0.001
```

## Steps to Run the Scripts

### 1. Create a Legacy Wallet and Address
Run the following commands to create a wallet and generate a legacy address:
```sh
bitcoin-cli -regtest createwallet "main_wallet" false false "" false false
send_from_address=$(bitcoin-cli -regtest getnewaddress)
```

### 2. Mine Initial Blocks
Mine 101 blocks to unlock the coinbase rewards:
```sh
bitcoin-cli -regtest generatetoaddress 101 "$send_from_address"
```

Check the current balance:
```sh
current_balance=$(bitcoin-cli -regtest getbalance)
echo "Current balance: $current_balance"
```

### 3. Create a Timelocked P2SH Address
Run the `create_timelocked_p2sh.py` script to generate a timelocked P2SH address:
```sh
python create_timelocked_p2sh.py --key <private_key> --locktime <locktime>
```
- Replace `<private_key>` with the WIF private key.
- Replace `<locktime>` with the desired absolute locktime (block height or UNIX timestamp).

### 4. Fund the Timelocked Address
Send funds to the generated P2SH address and mine a block to confirm:
```sh
bitcoin-cli -regtest sendtoaddress <timelocked_address> 1.0
bitcoin-cli -regtest generatetoaddress 1 "$send_from_address"
```
Repeat this step as needed to send multiple transactions.

Mine 10 additional blocks:
```sh
bitcoin-cli -regtest generatetoaddress 10 "$send_from_address"
```
### 5. Verify Block Count
Check the current block count to ensure it is less than the locktime:
```sh
block_count=$(bitcoin-cli -regtest getblockcount)
echo "Current block count: $block_count"
```
### 6. Create a Destination Wallet and Address
Create a destination wallet and generate a legacy address:
```sh
bitcoin-cli -regtest createwallet "dest_wallet" false false "" false false
destination_address=$(bitcoin-cli -regtest -rpcwallet=dest_wallet getnewaddress "" legacy)
```
### 7. Attempt to Spend from the Timelocked Address (Before Timelock)
Run the `spend_timelocked_p2sh.py` script to attempt spending from the timelocked address:
```sh
python ./spend_timelocked_p2sh.py --locktime $locktime --private_key "$private_key" --p2sh_address "$timelocked_address" --destination_p2pkh_address $destination_address
```
This transaction will be rejected because the timelock has not yet been reached.

### 8. Mine Blocks to Satisfy the Timelock
Mine blocks until the timelock is satisfied:
```sh
bitcoin-cli -regtest generatetoaddress $locktime "$send_from_address"
```
### 9. Spend from the Timelocked Address (After Timelock)
Run the `spend_timelocked_p2sh.py` script again to spend from the timelocked address:
```sh
python ./spend_timelocked_p2sh.py --locktime $locktime --private_key "$private_key" --p2sh_address "$timelocked_address" --destination_p2pkh_address $destination_address
```

### 10. Verify the Transaction
Check the mempool to ensure the transaction is broadcasted:
```sh
bitcoin-cli -regtest getrawmempool
```
Mine one more block to confirm the transaction:
```sh
bitcoin-cli -regtest generatetoaddress 1 "$send_from_address"
```

### 11. Check the Destination Address Balance
Verify the balance of the destination address:
```sh
bitcoin-cli -regtest scantxoutset start "[\"addr($destination_address)\"]"
```
## Notes
- Replace placeholders (e.g., `<private_key>`, `<timelocked_address>`) with actual values.
- Ensure the `bitcoin-cli` commands are executed in the same environment as the `bitcoind` daemon.