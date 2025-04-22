# activate the conda environment stemmed from ./requirements.txt
# python version = 3.10.16
# delete /home/<USER>/.bitcoin/regtest and let the the following commands be executed

# Create a legacy wallet and a legacy address to send the bitcoins to the P2SH address
bitcoin-cli -regtest createwallet "main_wallet" false false "" false false
send_from_address=$(bitcoin-cli -regtest getnewaddress)
echo "========================="

# Mine 101 blocks so as to be able to spend the reward of mining the first block
bitcoin-cli -regtest generatetoaddress 101 "$send_from_address" > /dev/null 2>&1
echo "Mined 101 blocks."
current_balance=$(bitcoin-cli -regtest getbalance)
echo "Current balance: $current_balance"
echo "========================="

# Generate p2sh address
private_key="cRvyLwCPLU88jsyj94L7iJjQX5C2f8koG4G2gevN4BeSGcEvfKe9"
locktime=200
# python ./create_timelocked_p2sh.py --key $private_key --locktime $locktime
timelocked_address=$(
  python ./create_timelocked_p2sh.py \
    --key "$private_key" \
    --locktime $locktime \
  | sed -n 's/^Timelocked P2SH Address: //p'
)

echo "Timelocked P2SH Address is: $timelocked_address"
echo "========================="

# Send 10 times 1 BTC to the timelocked address
for i in {1..10}
do
  bitcoin-cli -regtest sendtoaddress "$timelocked_address" 1.0
  bitcoin-cli -regtest generatetoaddress 1 "$send_from_address" > /dev/null 2>&1
  echo "Sending 1 bitcoin to the timelocked address and mining 1 block (iteration $i)."
done
# mine 10 blocks on the send_from_address
bitcoin-cli -regtest generatetoaddress 10 "$send_from_address" > /dev/null 2>&1
echo "Mined 10 blocks."

# Print getblockcount to ensure the blocks count is less than 200
echo "========================="
block_count=$(bitcoin-cli -regtest getblockcount)
echo "Current block count: $block_count"

# Create a destination legacy wallet and create a legacy address to send the bitcoins from the P2SH address
echo "========================="
bitcoin-cli -regtest createwallet "dest_wallet" false false "" false false
destination_address=$(bitcoin-cli -regtest -rpcwallet=dest_wallet getnewaddress "" legacy)

# Try to send the bitcoins from the P2SH address to the destination address
# The tx will be rejected because the timelock is not yet reached
echo "========================="
python ./spend_timelocked_p2sh.py --locktime $locktime --private_key "$private_key" --p2sh_address "$timelocked_address" --destination_p2pkh_address $destination_address

# Mine $locktime blocks (silenced)
echo "========================="
bitcoin-cli -regtest generatetoaddress $locktime "$send_from_address" > /dev/null 2>&1
echo "Mined $locktime blocks."

# Try to send again the bitcoins from the P2SH address to the destination address
# The tx will be accepted because the timelock is reached
echo "========================="
python ./spend_timelocked_p2sh.py --locktime $locktime --private_key "$private_key" --p2sh_address "$timelocked_address" --destination_p2pkh_address $destination_address

# Get the raw mempool so as to ensure the transaction is in the mempool
echo "========================="
echo "Printing the raw mempool:"
bitcoin-cli -regtest getrawmempool

# Mine 1 block to execute the transaction
echo "========================="
bitcoin-cli -regtest generatetoaddress 1 "$send_from_address" > /dev/null 2>&1
echo "Mined 1 block."

# Print the amount of bitcoins in the destination address
echo "========================="
echo "Amount of bitcoins in the destination address:"
bitcoin-cli -regtest scantxoutset start "[\"addr($destination_address)\"]"

# Script is terminated
echo "Script execution completed."

