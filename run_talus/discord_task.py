from better_automation.discord import DiscordClient, DiscordAccount
from utils.utils import retry, check_res_status, resolve_cf
from pydantic import Field
import warnings
from better_automation.discord.errors import Forbidden, Unauthorized
from urllib.parse import urlparse, parse_qs
from .utils import verify_or_relogin
warnings.filterwarnings("ignore", message="coroutine .* was never awaited", category=RuntimeWarning)


class CustomDiscordAccount(DiscordAccount):
    auth_token: str | None = Field(default=None, pattern=r"^[A-Za-z0-9+._-]{70}|[A-Za-z0-9+._-]{72}$")


class DiscordTask:
    def __init__(self, token, session, client, logger, db_manager):
        self.token = token
        self.logger = logger
        self.session = session
        self.client = client
        self.db_manager = db_manager
        self.discord_account: DiscordAccount = CustomDiscordAccount(token)

    def update_token(self, new_token):
        self.token = new_token
        self.discord_account = CustomDiscordAccount(self.token)

    async def connect(self):
        self.logger.info("Starting binding discord to talus...")
        async with DiscordClient(self.discord_account, proxy=self.session.proxies.get('http'), verify=False) as discord:
            discord_data = await self.get_discord_data()
            location = discord_data.headers.get('location')
            parsed_url = urlparse(location)
            query_params = parse_qs(parsed_url.query)
            state = query_params.get('state', [None])[0]
            redirect_uri = query_params.get('redirect_uri', [None])[0]
            client_id = query_params.get('client_id', [None])[0]
            oauth_data = {
                'client_id': client_id,
                'response_type': 'code',
                'redirect_uri': redirect_uri,
                'scope': 'identify',
                'state': state
            }
            oauth_data.pop('redirect_uri')
            try:
                bind_code = await discord.bind_app(**oauth_data)
            except (Forbidden, Unauthorized):
                self.logger.error('Bad discord! Change token')
                return False
            await self.send_callback(bind_code, oauth_data.get('state'))
            await self.send_callback_v2(bind_code, oauth_data.get('state'))
            return True

    @retry()
    @check_res_status(expected_statuses=[200, 201, 307])
    @verify_or_relogin
    async def get_discord_data(self):
        url = 'https://hub.talus.network/api/discord/auth?redirect=https://hub.talus.network/loyalty'
        return await self.session.get(url, allow_redirects=False)

    @retry()
    @check_res_status(expected_statuses=[200, 201, 307])
    @verify_or_relogin
    async def send_callback(self, code, state):
        url = 'https://snag-render.com/api/discord/auth/callback'
        params = {
            'state': state,
            'code': code
        }
        return await self.session.get(url, params=params)

    @retry()
    @check_res_status(expected_statuses=[200, 201, 307])
    @verify_or_relogin
    async def send_callback_v2(self, code, state):
        url = 'https://hub.talus.network/api/discord/auth/connect'
        params = {
            'state': state,
            'code': code
        }
        return await self.session.get(url, params=params)
