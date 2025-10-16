from database.engine import DbManager
from sqlalchemy import select
from utils.client import Client
from utils.models import Proxy


class TalusDbManager(DbManager):
    def __init__(self, db_path, base):
        super().__init__(db_path, base)

    async def create_base_note(self, pk, proxy, twitter_token, discord_token, email, sol_wallet, sui_wallet):
        await super().create_base_note(pk, proxy, twitter_token=twitter_token,
                                       discord_token=discord_token, email=email, sol_wallet=sol_wallet,
                                       sui_wallet=sui_wallet)

    async def get_run_data(self):
        async with self.session.begin():
            result = await self.session.execute(select(self.base))
            users = result.scalars().all()
            return [{'client': Client(user.private_key),
                     'proxy': Proxy(user.proxy),
                     'twitter_token': user.twitter_token,
                     'discord_token': user.discord_token,
                     'email': user.email,
                     'sol_wallet': user.sol_wallet,
                     'sui_wallet': user.sui_wallet}
                    for user in users]
