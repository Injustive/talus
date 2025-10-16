from urllib.parse import urlparse, parse_qs

import twitter
from twitter import Client
from utils.utils import retry, check_res_status, generate_url_safe_base64, generate_random
from contextlib import asynccontextmanager
from twitter.errors import (BadAccountToken,
                            AccountLocked,
                            AccountSuspended,
                            FailedToFindDuplicatePost,
                            ServerError,
                            HTTPException)
from utils.utils import (BadTwitterTokenException,
                         LockedTwitterTokenException,
                         SuspendedTwitterTokenException,
                         TwitterException,
                         sleep)
from .utils import verify_or_relogin


class TwitterTask:
    def __init__(self, token, session, client, logger, db_manager):
        self.session = session
        self.token = token
        self.account = twitter.Account(auth_token=token)
        self.twitter_client = None
        self.logger = logger
        self.db_manager = db_manager
        self.client = client

    def update_token(self, new_token):
        self.token = new_token
        self.account = twitter.Account(auth_token=new_token)
        self.twitter_client = None

    @asynccontextmanager
    async def twitter_session(self):
        await sleep(3, 60)
        try:
            if not self.twitter_client:
                self.logger.info('Opening new Twitter client session...')
                self.twitter_client = await Client(self.account,
                                                   proxy=self.session.proxies.get('http'),
                                                   auto_relogin=True).__aenter__()
            yield self.twitter_client
        except BadAccountToken:
            self.logger.error(f'Bad token! Maybe replace it {self.token}')
            raise BadTwitterTokenException(token=self.token)
        except AccountLocked:
            self.logger.error(f'Twitter account is locked! {self.token}')
            raise LockedTwitterTokenException(token=self.token)
        except AccountSuspended:
            self.logger.error(f'Twitter account is suspended! {self.token}')
            raise SuspendedTwitterTokenException(token=self.token)
        except (FailedToFindDuplicatePost, ServerError, HTTPException) as e:
            raise TwitterException(f'{self.token} | {e}')
        except KeyError:
            raise TwitterException(f'{self.token} | You need to wait some time to send new request to Twitter')

    async def connect(self):
        async with self.twitter_session():
            callback_response = await self.get_twitter_data()
            location = callback_response.headers.get('location')
            parsed_url = urlparse(location)
            query_params = parse_qs(parsed_url.query)
            code_challenge = query_params.get('code_challenge', [None])[0]
            state = query_params.get('state', [None])[0]
            redirect_uri = query_params.get('redirect_uri', [None])[0]
            client_id = query_params.get('client_id', [None])[0]
            oauth2_data = {
                "response_type": "code",
                "client_id": client_id,
                "code_challenge": code_challenge,
                "code_challenge_method": "plain",
                "redirect_uri": redirect_uri,
                "state": state,
                "scope": "users.read tweet.read",
            }
            code = await self.twitter_client.oauth2(**oauth2_data)
            await self.send_callback(state, code)
            await self.send_callback_v2(state, code)
            return code

    @retry()
    @check_res_status(expected_statuses=[200, 201, 307])
    @verify_or_relogin
    async def get_twitter_data(self):
        url = 'https://hub.talus.network/api/twitter/auth?redirect=https://hub.talus.network/loyalty'
        return await self.session.get(url, allow_redirects=False)

    @retry()
    @check_res_status(expected_statuses=[200, 201, 307])
    @verify_or_relogin
    async def send_callback(self, state, code):
        url = 'https://snag-render.com/api/twitter/auth/callback'
        params = {
            'state': state,
            'code': code
        }
        return await self.session.get(url, params=params)

    @retry()
    @check_res_status(expected_statuses=[200, 201, 307])
    @verify_or_relogin
    async def send_callback_v2(self, state, code):
        url = 'https://hub.talus.network/api/twitter/auth/connect'
        params = {
            'state': state,
            'code': code
        }
        return await self.session.get(url, params=params)

    async def complete_follow_task(self, username):
        username = username.replace('@', '')
        async with self.twitter_session():
            user_info = await self.twitter_client.request_user_by_username(username=username)
            await self.twitter_client.follow(user_info.id)
            self.logger.success(f'Followed {username} successfully!')
            return True

    async def quote_post(self, main_text):
        async with self.twitter_session():
            quote_id = await self.twitter_client.tweet(text=main_text)
            self.logger.success(f'Quoted post successfully!')
            return quote_id