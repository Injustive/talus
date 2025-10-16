from pybitget import Client
from decimal import Decimal, ROUND_DOWN


class BITGET:
    def __init__(self, account, log=None):
        self.account = account
        self.client = Client(
            self.account.API_KEY,
            self.account.SECRET_KEY ,
            passphrase=self.account.PASSPHRASE,
            use_server_time=True
        )
        self.logger = log

    def get_main_uid(self):
        info = self.client.spot_get_ApiKeyInfo()
        return str(info["data"]["user_id"])

    def sub_to_main_transfer(self, from_uid: str, coin: str, amount: str,
                             from_type: str = "spot", to_type: str = "spot",
                             client_oid: str | None = None):
        main_uid = self.get_main_uid()
        return self.client.spot_sub_transfer(
            from_type, to_type, amount, coin, client_oid, from_uid, main_uid
        )

    def get_sub_assets(self):
        res = self.client.spot_get_sub_account_assets()
        data = res.get("data", []) or []
        return [{"user_id": x['userId'], "assets": x["spotAssetsList"]} for x in data if "userId" in x]

    def quantize_amount(self, amount: Decimal, precision: int = 8):
        q = Decimal(10) ** -precision
        return str(amount.quantize(q, rounding=ROUND_DOWN))

    def get_available_coin_amount(self, assets: list[dict], coin):
        for a in assets or []:
            if a.get("coinName") == coin:
                try:
                    return Decimal(a.get("available", "0"))
                except Exception:
                    return Decimal("0")
        return Decimal("0")

    def withdraw_asset_from_all_subs(self, coin):
        subs = self.get_sub_assets()
        if not subs:
            self.logger.info(f"Subaccounts with asset not found")
            return
        main_uid = self.get_main_uid()
        for sub in subs:
            sub_uid = str(sub["user_id"])
            assets = sub['assets']
            amt = self.get_available_coin_amount(assets, coin)
            if amt <= 0:
                continue
            amt_str = self.quantize_amount(amt, precision=8)
            self.logger.info(f"[{sub_uid}] MOVE available = {amt} -> send {amt_str}")
            try:
                resp = self.client.spot_sub_transfer("spot", "spot", amt_str, coin, None, sub_uid, main_uid)
                self.logger.info(f"[{sub_uid}] {resp}")
            except Exception as e:
                self.logger.error(f"[{sub_uid}] {e}")
