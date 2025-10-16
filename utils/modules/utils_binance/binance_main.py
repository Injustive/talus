import ccxt


class BINANCE:
    def __init__(self, account, log=None):
        self.account = account
        self.client = ccxt.binance({
            'apiKey': self.account.API_KEY,
            'secret': self.account.SECRET_KEY,
            'enableRateLimit': True,
            'options': {
                'defaultType': 'spot'
            }
        })
        self.logger = log

    def withdraw_to(self, address, amount_to_withdrawal, symbol_withdraw, network="MOVE"):
        try:
            self.client.withdraw(
                code=symbol_withdraw,
                amount=amount_to_withdrawal,
                address=address,
                tag=None,
                params={
                    "network": network
                }
            )
            self.logger.success(f"{address} | {amount_to_withdrawal}")
            return True
        except Exception as error:
            self.logger.error(f"{address} | ERROR : {error}")
            return False