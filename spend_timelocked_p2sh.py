from bitcoinutils.setup import setup
from bitcoinutils.utils import to_satoshis
from bitcoinutils.transactions import Sequence
from bitcoinutils.transactions import Transaction, TxInput, TxOutput
from bitcoinutils.keys import P2pkhAddress, PrivateKey, P2shAddress
from bitcoinutils.script import Script
from bitcoinutils.constants import TYPE_ABSOLUTE_TIMELOCK
import subprocess
import json
import argparse


def query_utxos(address, min_conf=6):
    """
    Returns the total amount (in BTC) available to spend from `address`,
    counting only UTXOs with > min_conf confirmations.
    """
    try:
        # build and run the scan
        scan_list = json.dumps([{"desc": f"addr({address})"}])
        cmd = ["bitcoin-cli", "-regtest", "scantxoutset", "start", scan_list]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)

        if not data.get("success", False):
            return False
        else:
            return data

    except subprocess.CalledProcessError as e:
        print("RPC error scanning UTXO set:", e.stderr.strip())
    except (json.JSONDecodeError, KeyError) as e:
        print("Error parsing scantxoutset response:", str(e))
    except Exception as e:
        print("Unexpected error:", str(e))

    return False


def get_fee_rate():
    """
    Ask the node for a 6‐block estimate. If it comes back empty or zero,
    fall back to the node's minrelaytxfee or a hardcoded default.
    **Returns fee rate in satoshis per byte.**
    """
    # 1) try estimatesmartfee
    try:
        out = subprocess.run(
            ["bitcoin-cli", "-regtest", "estimatesmartfee", "6"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        fee_data = json.loads(out)
        feerate_btc_per_kb = fee_data.get("feerate", 0) or 0
        # Bitcoin Core returns BTC per kB → convert to sat/B:
        if feerate_btc_per_kb > 0:
            return feerate_btc_per_kb * 1e5  # 1 BTC/kB = 1e5 sat/B
    except Exception as e:
        print("Error getting fee rate from estimatesmartfee:", str(e))

    # 2) fallback: ask for minrelaytxfee (BTC/kB) → sat/B
    try:
        out = subprocess.run(
            ["bitcoin-cli", "-regtest", "getmempoolinfo"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        mpinfo = json.loads(out)
        minrelay_btc_per_kb = mpinfo.get("minrelaytxfee", 0.00001000)
        return minrelay_btc_per_kb * 1e5
    except Exception as e:
        print("Error getting fee rate from getmempoolinfo:", str(e))

    # 3) final fallback
    return 10  # sats per byte


def compute_total_fee(p2sh_utxos, p2pkh_pk, redeem_script, dest_address):
    """
    Compute and return the fee (in satoshis) required to sweep all UTXOs
    in `p2sh_utxos` through the CLTV‑wrapped redeem_script into `to_addr`.
    """
    # 1) fetch fee rate (sat/B), warn if falling back
    sat_per_byte = get_fee_rate()
    if sat_per_byte <= 0 or sat_per_byte == 10:
        print(f"[WARNING] using fallback fee rate: {sat_per_byte:.2f} sat/B")

    # 2) count inputs/outputs
    num_inputs = len(p2sh_utxos["unspents"])
    num_outputs = 1  # single P2PKH destination

    # 3) helper to size varints
    def varint_size(n: int) -> int:
        if n < 0xFD:
            return 1
        elif n <= 0xFFFF:
            return 3
        elif n <= 0xFFFFFFFF:
            return 5
        else:
            return 9

    # 4) scriptSig size: push(sig) + push(pubkey) + push(redeem_script)
    sig_size = 73  # DER sig + sighash flag
    pubkey_size = len(bytes.fromhex(p2pkh_pk))  # should be 33
    redeem_raw = bytes.fromhex(
        redeem_script.to_hex()
    )  # raw bytes of your CLTV‐P2PKH script
    redeem_size = len(redeem_raw)
    script_sig_sz = (1 + sig_size) + (1 + pubkey_size) + (1 + redeem_size)

    # 5) input size: outpoint(36) + varint(scriptSig) + scriptSig + sequence(4)
    input_size = 36 + varint_size(script_sig_sz) + script_sig_sz + 4

    # 6) output size: value(8) + varint(scriptPubKey) + scriptPubKey
    dest_raw = dest_address.to_script_pub_key().to_bytes()
    output_sz = 8 + varint_size(len(dest_raw)) + len(dest_raw)

    # 7) total vsize = version(4) + varint(nIn) + inputs + varint(nOut) + outputs + locktime(4)
    tx_vsize = (
        4
        + varint_size(num_inputs)
        + num_inputs * input_size
        + varint_size(num_outputs)
        + num_outputs * output_sz
        + 4
    )

    # 8) compute fee
    fee_sats = int(tx_vsize * sat_per_byte)
    fee_btc = fee_sats / 1e8
    print(f"Estimated tx size: {tx_vsize} bytes")
    print(
        f"Fee rate: {sat_per_byte:.2f} sat/B → fee = {fee_sats} sats ({fee_btc:.8f} BTC)"
    )

    return fee_sats


def varint_size(n: int) -> int:
    if n < 0xFD:
        return 1
    elif n <= 0xFFFF:
        return 3
    elif n <= 0xFFFFFFFF:
        return 5
    else:
        return 9


def validate_transaction(raw_signed_tx: str) -> bool:
    """
    Validate `raw_signed_tx` against the regtest mempool using testmempoolaccept.
    Prints the full result, any rejection reason, and returns True if it’s allowed.
    """
    payload = json.dumps([raw_signed_tx])
    cmd = ["bitcoin-cli", "-regtest", "testmempoolaccept", payload]

    try:
        completed = subprocess.run(
            cmd, capture_output=True, text=True, check=True
        )
        result = json.loads(completed.stdout)

        # pretty‑print the full response
        print("\ntestmempoolaccept result:")
        print(json.dumps(result, indent=2))

        # check the first (and only) entry
        entry = result[0]
        if not entry.get('allowed', False):
            reason = entry.get('reject-reason', 'Unknown reason')
            print("❌ Transaction failed:", reason)
            return False

        print("✅ Transaction is valid and would be accepted by the mempool.")
        return True

    except subprocess.CalledProcessError as e:
        print("RPC error running testmempoolaccept:", e.stderr.strip())
        return False
    except (json.JSONDecodeError, KeyError) as e:
        print("Error parsing testmempoolaccept response:", str(e))
        return False


def confirm_in_mempool(txid: str) -> bool:
    """
    Run `bitcoin-cli -regtest getrawmempool` and check whether `txid` is present.
    Returns True if found, False otherwise.
    """
    try:
        completed = subprocess.run(
            ["bitcoin-cli", "-regtest", "getrawmempool"],
            capture_output=True,
            text=True,
            check=True
        )
        mempool_list = json.loads(completed.stdout)

        if txid in mempool_list:
            print(f"✅ Transaction {txid} is now in the mempool.")
            return True
        else:
            print(f"❌ Transaction {txid} NOT found in the mempool.")
            return False

    except subprocess.CalledProcessError as e:
        print("RPC error running getrawmempool:", e.stderr.strip())
    except json.JSONDecodeError as e:
        print("Error parsing getrawmempool response:", str(e))

    return False


def main():
    parser = argparse.ArgumentParser(
        description="Spend from a timelocked P2SH address."
    )
    parser.add_argument(
        "--locktime",
        type=int,
        default=200,
        help="Absolute locktime (block height or UNIX timestamp).",
    )
    parser.add_argument(
        "--private_key",
        default="cRvyLwCPLU88jsyj94L7iJjQX5C2f8koG4G2gevN4BeSGcEvfKe9",
        help="Private key (WIF) to sign the transaction.",
    )
    parser.add_argument(
        "--p2sh_address",
        default="2N8Z3e2LZtfQskDTZsKakbA9scE9c7LLPaG",
        help="P2SH address to spend from.",
    )
    # Needs to be legacy address
    parser.add_argument(
        "--destination_p2pkh_address",
        default="mq6ktT46rqTaxncZifQS9aVCdzb3ZNjLJ2",
        help="P2PKH address to send the funds to.",
    )
    args = parser.parse_args()

    # setup regtest network
    setup("regtest")

    # Parse arguments
    # locktime
    locktime = args.locktime
    seq = Sequence(TYPE_ABSOLUTE_TIMELOCK, locktime)
    seq_for_n_seq = seq.for_input_sequence()
    assert seq_for_n_seq is not None

    # private key to recreate the redeem script
    p2pkh_sk = PrivateKey(str(args.private_key))
    p2pkh_pk = p2pkh_sk.get_public_key().to_hex()
    p2pkh_addr = p2pkh_sk.get_public_key().get_address()

    # P2SH address to spend from
    p2sh_address = P2shAddress(args.p2sh_address)

    # destination address (has to be legacy)
    dest_address = P2pkhAddress(args.destination_p2pkh_address)

    # query UTXOs for p2sh_address
    p2sh_address_utxos = query_utxos(address=p2sh_address.to_string(), min_conf=6)
    assert p2sh_address_utxos, "No UTXOs found for the given P2SH address."

    # calculate the total amount available to spend
    total_amount = sum(utxo["amount"] for utxo in p2sh_address_utxos["unspents"])
    print(
        f"Total amount available to spend from {p2sh_address.to_string()}: {total_amount} BTC"
    )

    # define redeem script
    redeem_script = Script(
        [
            seq.for_script(),
            "OP_CHECKLOCKTIMEVERIFY",
            "OP_DROP",
            "OP_DUP",
            "OP_HASH160",
            p2pkh_addr.to_hash160(),
            "OP_EQUALVERIFY",
            "OP_CHECKSIG",
        ]
    )

    # calculate fee cost
    fee_sats = compute_total_fee(p2sh_address_utxos, p2pkh_pk, redeem_script, dest_address)
    total_sats = to_satoshis(total_amount)
    send_sats = total_sats - fee_sats
    assert send_sats > 0, "Fee exceeds available funds!"

    # create txins and txouts
    txins = [TxInput(utxo["txid"], utxo["vout"], sequence=seq_for_n_seq) for utxo in p2sh_address_utxos["unspents"]]
    txouts = [TxOutput(send_sats, dest_address.to_script_pub_key())]

    # Create the transaction
    tx = Transaction(txins, txouts, locktime=seq.for_script().to_bytes(4, "little"))
    print("\nRaw unsigned transaction:\n" + tx.serialize())

    # sign all inputs
    for idx, txin in enumerate(txins):
        # sign the input with the redeem script
        sig = p2pkh_sk.sign_input(tx, idx, redeem_script)
        # set scriptSig: <sig> <pubkey> <redeem_script>
        tx.inputs[idx].script_sig = Script([sig, p2pkh_pk, redeem_script.to_hex()])

    # serialize and print
    signed_tx = tx.serialize()
    print("\nRaw signed transaction:\n" + signed_tx)
    print("\nTxId:", tx.get_txid())

    # validate transaction
    assert validate_transaction(signed_tx), "Transaction is invalid!"

    # send the transaction to mempool
    txid = subprocess.run(
        ["bitcoin-cli", "-regtest", "sendrawtransaction", signed_tx],
        capture_output=True, text=True, check=True
    ).stdout.strip()
    print("\nBroadcasted txid:", txid)


if __name__ == "__main__":
    main()
