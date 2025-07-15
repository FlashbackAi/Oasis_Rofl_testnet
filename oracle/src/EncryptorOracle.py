import asyncio
import os
from web3 import Web3
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
from dotenv import load_dotenv
from ContractUtility import ContractUtility
from RoflUtility import RoflUtility
from eth_account import Account
# Load .env file
load_dotenv()

# Configuration (load from environment variables)
SAPPHIRE_TESTNET_RPC = os.getenv("SAPPHIRE_TESTNET_RPC", "https://testnet.sapphire.oasis.dev")
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS", "0x0ACa9341750996ceA163e0c9eE74a5dCd1307E78")
ROFL_APP_ID = os.getenv("ROFL_APP_ID", "0x00d7b499d75788746296e1aae4bfff8de4a74be2")
ORACLE_PRIVATE_KEY = os.getenv("ORACLE_PRIVATE_KEY")

class EncryptorOracle:
    def __init__(self, contract_address: str, network_name: str, rofl_utility: RoflUtility, secret: str):
        # Initialize ContractUtility with network and private key
        self.contract_utility = ContractUtility(network_name, secret)
        self.rofl_utility = rofl_utility
        self.w3 = self.contract_utility.w3

        # Load Encryptor contract ABI
        try:
            self.abi, _ = self.contract_utility.get_contract('Encryptor')
        except FileNotFoundError as e:
            raise FileNotFoundError(f"Encryptor.json not found in contracts/out/Encryptor.sol: {e}")
        except Exception as e:
            raise ValueError(f"Failed to load Encryptor contract ABI: {e}")

        # Initialize contract
        if not self.w3.is_address(contract_address):
            raise ValueError(f"Invalid contract address: {contract_address}")
        self.contract = self.w3.eth.contract(address=self.w3.to_checksum_address(contract_address), abi=self.abi)

        # Validate ROFL_APP_ID (must be 21 bytes)
        try:
            self.rofl_app_id_bytes = bytes.fromhex(ROFL_APP_ID[2:])
            if len(self.rofl_app_id_bytes) != 21:
                raise ValueError(f"Invalid ROFL_APP_ID length: expected 21 bytes, got {len(self.rofl_app_id_bytes)} bytes")
        except ValueError as e:
            raise ValueError(f"Invalid ROFL_APP_ID format: {e}")

        # Verify contract roflAppID
        try:
            contract_rofl_app_id = self.contract.functions.roflAppID().call()
            if contract_rofl_app_id != self.rofl_app_id_bytes:
                raise ValueError(f"ROFL_APP_ID mismatch: contract expects {contract_rofl_app_id.hex()}, provided {ROFL_APP_ID}")
        except Exception as e:
            raise ValueError(f"Failed to verify contract roflAppID: {e}")

    def set_oracle_address(self):
        """Set the Oracle address in the contract if not already set."""
        try:
            current_oracle = self.contract.functions.oracle().call()
            if current_oracle.lower() == self.w3.eth.default_account.lower():
                print(f"Oracle already set to {current_oracle}")
                return
            if current_oracle != "0x0000000000000000000000000000000000000000":
                print(f"Warning: Oracle is set to {current_oracle}, attempting to update to {self.w3.eth.default_account}")

            # SECURITY WARNING: setOracle lacks onlyTEE modifier, making it vulnerable.
            # Consider updating contract to: function setOracle(address newOracle) external onlyTEE(roflAppID)
            tx_params = self.contract.functions.setOracle(self.w3.eth.default_account).build_transaction({
                'gas': 100000,
                'gasPrice': self.w3.eth.gas_price
            })
            res = self.rofl_utility.submit_tx(tx_params)
            # print(tx_hash)
            # if tx_hash is None:
            #     # ACK-only mode: rofl-appd said “ok”, but didn’t return a hash
            #     print(f"✅ Oracle address set to {self.w3.eth.default_account} (ACK mode, no tx-hash)")
            #     return

            # # full-hash mode: wait for confirmation on chain
            # tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            # if tx_receipt.status == 1:
            #     print(f"✅ Oracle address set to {self.w3.eth.default_account}, tx={tx_hash.hex()}")
            # else:
            #     print(f"❌ Failed to set oracle address, tx={tx_hash.hex()}")

        except Exception as e:
            print(f"Error setting oracle address: {e}")
            raise

    def encrypt_data(self, data: bytes) -> bytes:
        """Encrypt data using AES with roflAppID as the key."""
        try:
            # Ensure key is 16 bytes for AES-128
            key = self.rofl_app_id_bytes[:16]
            # Generate a random IV
            iv = get_random_bytes(16)
            # Initialize AES cipher in CBC mode
            cipher = AES.new(key, AES.MODE_CBC, iv)
            # Pad data to be multiple of 16 bytes
            padding_length = 16 - (len(data) % 16)
            padded_data = data + bytes([padding_length] * padding_length)
            # Encrypt
            ciphertext = cipher.encrypt(padded_data)
            # Return IV + ciphertext (base64 encoded)
            return base64.b64encode(iv + ciphertext)
        except Exception as e:
            print(f"Encryption error: {e}")
            raise

    async def log_loop(self, poll_interval):
        """Poll for RequestSubmitted events and process them."""
        print(f"Listening for RequestSubmitted events...", flush=True)
        while True:
            try:
                logs = self.contract.events.RequestSubmitted().get_logs(from_block=self.w3.eth.block_number)
                print(logs)
                for log in logs:
                    user = log.args.user
                    request_id = log.args.requestId
                    print(f"New request detected: user={user}, requestId={request_id}")

                    # Validate requestId using getRequestCount
                    try:
                        request_count = self.contract.functions.getRequestCount(user).call()
                        print(f"Request count for user {user}: {request_count}")
                        if request_id >= request_count:
                            print(f"Invalid requestId {request_id} for user {user}: only {request_count} requests exist")
                            continue
                    except Exception as e:
                        if '0x82b42900' in str(e):
                            print(f"InvalidRequestId error for user {user}, requestId {request_id} in getRequestCount")
                        elif '0x3a6d8c99' in str(e):
                            print(f"UnauthorizedOracle error for user {user}, requestId {request_id} in getRequestCount")
                        elif '0x82af4947' in str(e):
                            print(f"Unauthorized error for user {user}, requestId {request_id} in getRequestCount")
                        else:
                            print(f"Error fetching request count for user {user}: {e}")
                        continue

                    # Fetch request data
                    try:
                        requests = self.contract.functions.getRequests(user).call()
                        request_data = requests[request_id]
                        print(f"Fetched request data for user {user}, requestId {request_id}: {request_data.hex()}")
                    except Exception as e:
                        if '0x82b42900' in str(e):
                            print(f"InvalidRequestId error for user {user}, requestId {request_id} in getRequests")
                        else:
                            print(f"Error fetching requests for user {user}: {e}")
                        continue

                    # Check if request is already processed
                    try:
                        results = self.contract.functions.getResults(user).call()
                        if any(result[0] == request_id for result in results):
                            print(f"Request {request_id} for user {user} already processed")
                            continue
                    except Exception as e:
                        print(f"Error fetching results for user {user}: {e}")
                        continue

                    # Encrypt the request data
                    try:
                        encrypted_result = self.encrypt_data(request_data)
                        print(f"Encrypted result for user {user}, requestId {request_id}: {encrypted_result.hex()}")
                    except Exception as e:
                        print(f"Encryption failed for requestId {request_id}: {e}")
                        continue

                    # Submit the result
                    try:
                        tx_params = self.contract.functions.submitResult(
                            encrypted_result,
                            request_id,
                            user
                        ).build_transaction({
                            'gas': 200000,
                            'gasPrice': self.w3.eth.gas_price
                        })
                        res = self.rofl_utility.submit_tx(tx_params)

                        # if tx_hash is None:
                        #     # ACK-only mode: rofl-appd said “ok”, but didn’t return a hash
                        #     print(f"✅ Oracle address set to {self.w3.eth.default_account} (ACK mode, no tx-hash)")
                        #     return

                        # # full-hash mode: wait for confirmation on chain
                        # tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
                        # if tx_receipt.status == 1:
                        #     print(f"✅ Oracle address set to {self.w3.eth.default_account}, tx={tx_hash.hex()}")
                        # else:
                        #     print(f"❌ Failed to set oracle address, tx={tx_hash.hex()}")
                    except Exception as e:
                        print(f"Error submitting result for user={user}, requestId={request_id}: {e}")

                await asyncio.sleep(poll_interval)
            except Exception as e:
                print(f"Error in polling loop: {e}")
                await asyncio.sleep(poll_interval)

    def run(self) -> None:
        """Run the Oracle."""
        self.set_oracle_address()
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(asyncio.gather(self.log_loop(10)))
        finally:
            loop.close()

if __name__ == "__main__":
    # Initialize RoflUtility
    rofl_utility = RoflUtility()
    secret = rofl_utility.fetch_key("flashback-test")
    # Initialize EncryptorOracle
    oracle = EncryptorOracle(
        contract_address=CONTRACT_ADDRESS,
        network_name="sapphire-testnet",
        rofl_utility=rofl_utility,
        secret=secret
    )

    # Run the Oracle
    oracle.run()
