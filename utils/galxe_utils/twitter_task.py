import twitter
from utils.utils import (BadTwitterTokenException,
                         LockedTwitterTokenException,
                         SuspendedTwitterTokenException,
                         TwitterException,
                         sleep)
from twitter import Client
from contextlib import asynccontextmanager
from twitter.errors import (BadAccountToken,
                            AccountLocked,
                            AccountSuspended,
                            FailedToFindDuplicatePost,
                            ServerError,
                            HTTPException)
from .tg_bot_notificator import send_tg_bot_request


class GalxeTwitterTask:
    def __init__(self, token, session, client, logger, db_manager):
        self.token = token
        self.session = session
        self.client = client
        self.twitter_account = twitter.Account(auth_token=token)
        self.twitter_client = None
        self.twitter_username = None
        self.logger = logger
        self.db_manager = db_manager

    @asynccontextmanager
    async def twitter_session(self):
        await sleep(3, 120)
        try:
            if not self.twitter_client:
                self.logger.info('Opening new Twitter client session...')
                self.twitter_client = await Client(self.twitter_account,
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

    async def connect_to_website(self, galxe_user_id):
        async with self.twitter_session():
            self.logger.info('Starting binding twitter...')
            try:
                tweet = f"Verifying my Twitter account for my #GalxeID gid:{galxe_user_id} @Galxe \n\n galxe.com/id "
                post_id = await self.twitter_client.tweet(text=tweet)
                return f'https://twitter.com/{self.twitter_account.username}/status/{post_id}'
            except FailedToFindDuplicatePost:
                self.logger.error('Failed to bind twitter. Reason: DUPLICATE_VERIFICATION_POST')
                raise

    async def follow_with_username(self, username):
        async with self.twitter_session():
            user_info = await self.twitter_client.request_user_by_username(username=username)
            await self.twitter_client.follow(user_info.id)
            self.logger.success(f'Followed {username} successfully!')

    async def quote_tweet(self, main_text, friends=None):
        async with self.twitter_session():
            if friends:
                friends = ', '.join(friends)
                main_text = main_text + " " + friends
            await self.twitter_client.tweet(text=main_text)
            self.logger.success(f'Quoted post successfully!')

    async def repost(self, tweet_id):
        async with self.twitter_session():
            await self.twitter_client.repost(tweet_id=tweet_id)
            self.logger.success(f'Retweeted post successfully!')

    async def like_post(self, tweet_id):
        async with self.twitter_session():
            await self.twitter_client.like(tweet_id)
            self.logger.success(f'Liked post successfully!')

    async def get_account_username(self):
        if not self.twitter_username:
            async with self.twitter_session():
                await self.twitter_client.establish_status()
                self.twitter_username = self.twitter_account.username
        return self.twitter_username
