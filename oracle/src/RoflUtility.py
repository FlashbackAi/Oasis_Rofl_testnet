import httpx
import json
import typing
from web3.types import TxParams
from hexbytes import HexBytes
from web3 import Web3

def strip_0x(value: str) -> str:
    """Remove **exactly** one 0x prefix; never eat valid leading zeros."""
    return value[2:] if value.startswith("0x") else value

class RoflUtility:
    ROFL_SOCKET_PATH = "/run/rofl-appd.sock"

    def __init__(self, url: str = ''):
        self.url = url

    def _appd_post(self, path: str, payload: typing.Any) -> typing.Any:
        transport = None
        if self.url and not self.url.startswith('http'):
            transport = httpx.HTTPTransport(uds=self.url)
            print(f"Using HTTP socket: {self.url}")
        elif not self.url:
            transport = httpx.HTTPTransport(uds=self.ROFL_SOCKET_PATH)
            print(f"Using unix domain socket: {self.ROFL_SOCKET_PATH}")

        client = httpx.Client(transport=transport)

        url = self.url if self.url and self.url.startswith('http') else "http://localhost"
        print(f"  Posting {json.dumps(payload)} to {url+path}")
        response = client.post(url + path, json=payload, timeout=None)
        return response

    def fetch_key(self, id: str) -> str:
        payload = {
            "key_id": id,
            "kind": "secp256k1"
        }

        path = '/rofl/v1/keys/generate'

        response = self._appd_post(path, payload)
        # print("in Rofl utility")
        print(response["key"])
        return response["key"]

    def submit_tx(self, tx: TxParams) -> HexBytes:
        """
        Sign & broadcast a raw eth transaction via rofl-appd and
        return the tx-hash as HexBytes.
        """

        payload = {
            "tx": {
                "kind": "eth",
                "data": {
                    "gas_limit": tx["gas"],
                    "gas_price": tx["gasPrice"],
                    "to":    strip_0x(tx["to"]),
                    "value": tx["value"],
                    "data":  strip_0x(tx["data"])
                },
            },
            "encrypt": False,
        }

        # ---- call rofl-appd ----------------------------------------------------
        return self._appd_post("/rofl/v1/tx/sign-submit", payload)
    
