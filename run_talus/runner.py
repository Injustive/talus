from .router import TalusRouter
from utils.runner import ModernRunner
from utils.utils import get_session, sleep, get_data_lines, get_new_db_path_name, build_db_path
from .task import Task
from .database.engine import TalusDbManager
from .database.models import TalusBaseModel
from .config import SLEEP_BETWEEN_WALLETS
import os
from .paths import *


class TalusRunner(ModernRunner):
    def __init__(self):
        self.Router = TalusRouter
        super().__init__()

    async def run_task(self, data, need_to_sleep=True):
        async with TalusDbManager(build_db_path(self.db_name), TalusBaseModel) as db_manager:
            proxy = data['proxy']
            client = data['client']
            twitter_token = data['twitter_token']
            discord_token = data['discord_token']
            email = data['email']
            sol_wallet = data['sol_wallet']
            sui_wallet = data['sui_wallet']
            session = get_session('https://hub.talus.network',
                                  proxy.session_proxy,
                                  user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")
            task = Task(session=session, client=client, db_manager=db_manager,
                        twitter_token=twitter_token, discord_token=discord_token, email=email,
                        sol_wallet=sol_wallet, sui_wallet=sui_wallet)
            if need_to_sleep:
                await sleep(*SLEEP_BETWEEN_WALLETS)
            await self.Router().route(task=task, action=self.action)()

    async def handle_db(self):
        if self.db_name == 'new':
            new_db = get_new_db_path_name()
            async with TalusDbManager(new_db, TalusBaseModel) as db_manager:
                await db_manager.create_tables()
                async with db_manager.session.begin():
                    try:
                        for curr in range(len(self.prepared_data['clients'])):
                                data = {key: value[curr] for key, value in self.prepared_data.items()}
                                pk = data['clients'].key
                                proxy = data['proxies'].proxy
                                twitter_token = data['twitter_tokens']
                                discord_token = data['discord_tokens']
                                email = data['emails']
                                sol_wallet = data['sol_wallets']
                                sui_wallet = data['sui_wallets']
                                await db_manager.create_base_note(pk,
                                                                  proxy,
                                                                  twitter_token=twitter_token,
                                                                  discord_token=discord_token,
                                                                  email=email,
                                                                  sol_wallet=sol_wallet,
                                                                  sui_wallet=sui_wallet)
                    except Exception:
                        os.remove(new_db)
                        raise
            self.db_name = new_db
        async with TalusDbManager(build_db_path(self.db_name), TalusBaseModel) as db_manager:
            return await db_manager.get_run_data()

    def prepare_data(self):
        prepared_data = super().prepare_data()
        twitter_tokens = self.justify_data(prepared_data['clients'], list(get_data_lines(TWITTER_TOKENS)))
        discord_tokens = self.justify_data(prepared_data['clients'], list(get_data_lines(DISCORD_TOKENS)))
        emails = self.justify_data(prepared_data['clients'], list(get_data_lines(EMAILS)))
        sol_wallets = self.justify_data(prepared_data['clients'], list(get_data_lines(SOL_WALLETS)))
        sui_wallets = self.justify_data(prepared_data['clients'], list(get_data_lines(SUI_WALLETS)))
        prepared_data.update({'twitter_tokens': twitter_tokens, 'discord_tokens': discord_tokens, 'emails': emails,
                              'sol_wallets': sol_wallets, 'sui_wallets': sui_wallets})
        return prepared_data