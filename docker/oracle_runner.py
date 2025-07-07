#!/usr/bin/env python3
"""
flashback-oracle runner
• Ensures the contract's oracle slot equals this EOA.
• Polls getPendingIndexes → encrypts → submitEncryptedData.
"""

import os, json, time, logging, sys
from dotenv import load_dotenv
from web3 import Web3
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ──────────────────────────────────────────────────────────────
#  ENV & WEB3 SETUP
# ──────────────────────────────────────────────────────────────
load_dotenv()  # pulls .env into the process

RPC_URL   = os.getenv("SAPPHIRE_TESTNET_RPC_URL", "https://testnet.sapphire.oasis.io")
CHAIN_ID  = int(os.getenv("CHAIN_ID",      "23295"))
ABI_FILE  = os.getenv("ABI_PATH",          "contract_abi.json")  # override if you move it

w3   = Web3(Web3.HTTPProvider(RPC_URL))
acct = w3.eth.account.from_key(os.getenv("PRIVATE_KEY"))

if not w3.is_connected():
    sys.exit("❌  Unable to reach Sapphire RPC")

with open(ABI_FILE) as f:
    abi = json.load(f)

contract = w3.eth.contract(
    address = Web3.to_checksum_address(os.getenv("CONTRACT_ADDRESS")),
    abi     = abi,
)

logging.basicConfig(
    level  = logging.INFO,
    format = "%(asctime)s %(levelname)s %(message)s",
)

# ──────────────────────────────────────────────────────────────
#  ONE-TIME ORACLE SELF-HEAL
# ──────────────────────────────────────────────────────────────
def set_oracle_if_needed() -> None:
    current = Web3.to_checksum_address(contract.functions.oracle().call({"from": acct.address}))
    if current == acct.address:
        logging.info("oracle() already set to runner address → OK")
        return

    logging.info(f"oracle() slot is {current} → attempting setOracle({acct.address})")
    try:
        tx = contract.functions.setOracle(acct.address).build_transaction({
            "from":      acct.address,
            "nonce":     w3.eth.get_transaction_count(acct.address),
            "gas":       150_000,
            "gasPrice":  w3.eth.gas_price,
            "chainId":   CHAIN_ID,
        })
        signed  = acct.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        logging.info(f"📌 setOracle TX confirmed in block {receipt.blockNumber}")
    except Exception as e:
        logging.warning(f"setOracle failed (likely not running inside ROFL TEE): {e}")

set_oracle_if_needed()

# ──────────────────────────────────────────────────────────────
#  CRYPTO HELPERS
# ──────────────────────────────────────────────────────────────
def encrypt(plaintext: str):
    key = get_random_bytes(32)        # AES-256
    iv  = get_random_bytes(16)        # 16-byte IV
    cipher = AES.new(key, AES.MODE_CTR, nonce=iv[:8])
    ciphertext = cipher.encrypt(plaintext.encode("utf-8"))
    return ciphertext, key, iv

def submit(idx, cipher, key, iv):
    nonce = w3.eth.get_transaction_count(acct.address)
    tx = contract.functions.submitEncryptedData(idx, cipher, key, iv).build_transaction({
        "from":     acct.address,
        "nonce":    nonce,
        "gas":      500_000,           # tune after first runs
        "gasPrice": w3.eth.gas_price,
        "chainId":  CHAIN_ID,
    })
    signed  = acct.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
    logging.info(f"🔐 idx {idx} → {tx_hash.hex()}")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    logging.info(f"✅ confirmed in block {receipt.blockNumber}")

# ──────────────────────────────────────────────────────────────
#  MAIN LOOP
# ──────────────────────────────────────────────────────────────
while True:
    try:
        pending = contract.functions.getPendingIndexes().call()
        if not pending:
            logging.info("No plaintexts pending → sleeping 30 s")
            time.sleep(30)
            continue

        for idx in pending:
            entry = contract.functions.getEntry(idx).call()
            plaintext, encrypted_flag = entry[0], entry[4]
            if encrypted_flag:
                continue
            cipher, key, iv = encrypt(plaintext)
            submit(idx, cipher, key, iv)

    except Exception as e:
        logging.error(f"Runner error: {e}")

    time.sleep(5)
