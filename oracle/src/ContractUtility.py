from web3 import Web3
from web3.middleware import SignAndSendRawMiddlewareBuilder
from eth_account.signers.local import LocalAccount
from eth_account import Account
import json
from sapphirepy import sapphire
from pathlib import Path


class ContractUtility:
    """
    Initializes the ContractUtility class.

    :param network_name: Name of the network to connect to
    :type network_name: str
    :return: None
    """

    def __init__(self, network_name: str, secret: str):
        networks = {
            "sapphire": "https://sapphire.oasis.io",
            "sapphire-testnet": "https://testnet.sapphire.oasis.io",
            "sapphire-localnet": "http://localhost:8545",
        }
        self.network = networks[network_name] if network_name in networks else network_name
        self.w3 = self.setup_web3_middleware(secret)

    def setup_web3_middleware(self, secret: str) -> Web3:
        if not all([secret]):
            raise Warning(
                "Missing required environment variables. Please set PRIVATE_KEY.")

        account: LocalAccount = Account.from_key(secret)
        # print("in COntract Utility:secret")
        # print(secret)
        # print("account addres")
        # print(account.address)
        provider = Web3.WebsocketProvider(self.network) if self.network.startswith("ws:") else Web3.HTTPProvider(self.network)
        w3 = Web3(provider)
        w3.middleware_onion.inject(SignAndSendRawMiddlewareBuilder.build(account), layer=0)
        w3 = sapphire.wrap(w3, account)
        w3.eth.default_account = account.address
        return w3

    def get_contract(self, contract_name: str) -> (list, str):
        """Fetches ABI of the given contract from the abi folder"""
        output_path = (Path(__file__).parent / f"{contract_name}.json").resolve()
        with open(output_path, "r") as file:
            contract_data = json.load(file)

        # Handle direct ABI array or full contract JSON
        abi = contract_data if isinstance(contract_data, list) else contract_data.get("abi", [])
        bytecode = contract_data.get("bytecode", {}).get("object", "") if isinstance(contract_data, dict) else ""
        return abi, bytecode
