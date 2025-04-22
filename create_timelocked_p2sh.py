'''
@File    :   create_timelocked_p2sh.py
@Time    :   04/2025
@Author  :   nikifori
@Version :   -

This script creates a P2SH address with an absolute timelock.
It sets up the regtest network and constructs a redeem script using CLTV.
The redeem script format is:
   <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG

Usage:
   python create_p2sh_absolutelock.py --locktime <absolute_locktime_value> [--pubkey <WIF_key>]

If no key is provided, a default testing key is used.
'''
import sys
import argparse

from bitcoinutils.setup import setup
from bitcoinutils.transactions import Sequence
from bitcoinutils.keys import PrivateKey, PublicKey, P2shAddress
from bitcoinutils.script import Script
from bitcoinutils.constants import TYPE_ABSOLUTE_TIMELOCK

def main():
    # 1. Parse command-line arguments
    parser = argparse.ArgumentParser(
    description="Create a timelocked P2SH address (absolute time lock)."
    )
    parser.add_argument(
        "--key",
        default="cRvyLwCPLU88jsyj94L7iJjQX5C2f8koG4G2gevN4BeSGcEvfKe9",
        help="Either a private key (WIF) or a public key (hex). Defaults to a sample WIF."
    )
    parser.add_argument(
        "--locktime",
        type=int,
        default=200,
        help=(
            "Absolute locktime. "
            "Use block height (e.g., 840000) or UNIX timestamp (e.g., 1767225600). "
            "Defaults to 200. Values <500000000 are interpreted as block heights."
        )
    )
    args = parser.parse_args()

    # 2. Set up the network to regtest
    setup("regtest")

    # 3. Determine if the input is a private key or a public key
    #    - If it's a private key, we'll derive its corresponding public key.
    #    - If it's a public key, use it directly.
    try:
        # Attempt to parse the input as a PrivateKey
        p2pkh_sk = PrivateKey(args.key)
        public_key = p2pkh_sk.get_public_key()
    except Exception:
        # If we fail to parse it as a PrivateKey, interpret it as a raw public key
        public_key = PublicKey(args.key)

    # 4. Create P2PKH-like portion with the given public key
    p2pkh_hash160 = public_key.get_address().to_hash160()

    seq = Sequence(TYPE_ABSOLUTE_TIMELOCK, args.locktime)

    # 5. Build the redeem script for an absolute timelock + P2PKH
    #
    #    Redeem script structure:
    #      <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP
    #      OP_DUP OP_HASH160 <pubKeyHash160> OP_EQUALVERIFY OP_CHECKSIG
    #
    #    If locktime < 500000000 then it's interpreted as a block height,
    #    otherwise it's interpreted as a UNIX timestamp.
    redeem_script = Script([
        seq.for_script(),
        "OP_CHECKLOCKTIMEVERIFY",
        "OP_DROP",
        "OP_DUP",
        "OP_HASH160",
        p2pkh_hash160,
        "OP_EQUALVERIFY",
        "OP_CHECKSIG"
    ])

    # 6. Construct the P2SH address from the redeem script
    p2sh_addr = P2shAddress.from_script(redeem_script)

    # 7. Print the P2SH address to the console
    print("Timelocked P2SH Address:", p2sh_addr.to_string())

    # (Optional) print the redeem script for debugging
    print("Redeem Script:", redeem_script.to_hex())

if __name__ == "__main__":
    main()
