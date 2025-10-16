from better_automation.discord import DiscordClient, DiscordAccount
from pydantic import Field
from utils.utils import retry, check_res_status, generate_url_safe_base64, generate_random
import warnings
from better_automation.discord.errors import Forbidden, Unauthorized


warnings.filterwarnings(
    "ignore",
    message="coroutine .* was never awaited",
    category=RuntimeWarning,
)


class CustomDiscordAccount(DiscordAccount):
    auth_token: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z0-9+._-]{70}|[A-Za-z0-9+._-]{72}$",
    )


class DiscordTask:
    def __init__(self, token, session, client, logger, db_manager):
        self.token = token
        self.logger = logger
        self.session = session
        self.client = client
        self.discord_account: DiscordAccount = CustomDiscordAccount(token)
        self.db_manager = db_manager

    async def connect(self, oauth_data):
        async with DiscordClient(
                self.discord_account, proxy=self.session.proxies.get("http"), verify=False
        ) as discord:
            oauth_data.pop("redirect_uri", None)
            oauth_data.pop("prompt", None)
            state = oauth_data.get("state")
            try:
                bind_code = await discord.bind_app(**oauth_data)
            except (Forbidden, Unauthorized):
                self.logger.error('Bad discord')
                return False
            self.logger.success("Successfully got bind code for Discord!")
            await self.callback_request(state, bind_code)
            await self.check_discord_account(state.split(',')[-1], bind_code)
            verify_response = (await self.verify_discord_account(state.split(',')[-1], bind_code)).json()['data']
            if verify_response['verifyDiscordAccount']:
                self.logger.success("Successfully connected Discord to Galxe!")
                return True
            else:
                self.logger.error(f"Failed to connect Discord to Galxe! {verify_response}")

    @retry()
    @check_res_status()
    async def verify_discord_account(self, state, bind_code):
        url = 'https://graphigo.prd.galaxy.eco/query'
        json = {
            'operationName': 'VerifyDiscord',
            'query': 'mutation VerifyDiscord($input: VerifyDiscordAccountInput!) {\n  verifyDiscordAccount(input: $input) {\n    address\n    discordUserID\n    discordUserName\n    __typename\n  }\n}\n',
            'variables': {
                'input': {
                    'address': f"EVM:{self.client.address}",
                    'state': state,
                    'token': bind_code,
                },
            },
        }
        return await self.session.post(url, json=json)

    @retry()
    @check_res_status()
    async def callback_request(self, state, code):
        url = 'https://app.galxe.com'
        params = {
            'code': code,
            'state': state
        }
        return await self.session.get(url, params=params)

    @retry()
    @check_res_status()
    async def check_discord_account(self, state, code):
        url = 'https://graphigo.prd.galaxy.eco/query'
        json_data = {
            'operationName': 'checkDiscordAccount',
            'variables': {
                'input': {
                    'address': f'EVM:{self.client.address}',
                    'token': code,
                    'state': state,
                },
            },
            'query': 'mutation checkDiscordAccount($input: VerifyDiscordAccountInput!) {\n  checkDiscordAccount(input: $input) {\n    address\n    discordUserID\n    __typename\n  }\n}',
        }
        return await self.session.post(url, json=json_data)




