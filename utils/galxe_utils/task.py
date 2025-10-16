import asyncio
import uuid
from datetime import datetime, timezone, timedelta
import random
from .config import ACTUAL_CAPTCHA_SOLVER
from .utils import galxe_task_retry
from .db import GalxeDb
from .twitter_task import GalxeTwitterTask
from .email_client import EmailClient
from .exceptions import EmailVerificationException
from utils.utils import (Logger, generate_random, retry,
                         check_res_status, sleep, BadTwitterTokenException,
                         LockedTwitterTokenException, SuspendedTwitterTokenException, TwitterException)
from faker import Faker
from utils.email import email
from urllib.parse import urlparse, parse_qs, urlencode, quote
from .discord_task import DiscordTask


global_lock = asyncio.Lock()


class ModernGalxeTask:
    def __init__(self, session,
                 client,
                 logger,
                 db_manager,
                 email=None,
                 twitter_token=None,
                 discord_token=None,
                 captcha_solver=None):
        self.session = session
        self.client = client
        self.logger = logger
        self.db_manager = db_manager
        self.email = email
        self.twitter_token = twitter_token
        self.discord_token = discord_token
        self.captcha_solver = captcha_solver

    async def is_address_registered(self):
        is_address_registered_response = (await self.is_address_registered_request()).json()
        return is_address_registered_response["data"]["galxeIdExist"]

    @staticmethod
    def get_random_username(min_lenght=6) -> str:
        return Faker().user_name().ljust(min_lenght, str(random.randint(1, 9)))

    @retry()
    @check_res_status()
    async def is_address_registered_request(self):
        url = 'https://graphigo.prd.galaxy.eco/query'
        self.session.headers.update({'request-id': str(uuid.uuid4())})
        json_data = {
            'operationName': 'GalxeIDExist',
            'variables': {
                'schema': f'EVM:{self.client.address}',
            },
            'query': 'query GalxeIDExist($schema: String!) {\n  galxeIdExist(schema: $schema)\n}\n',
        }
        return await self.session.post(url, json=json_data)

    @retry()
    @check_res_status()
    async def check_if_username_exist(self, username):
        url = 'https://graphigo.prd.galaxy.eco/query'
        json_data = {
            'operationName': 'IsUsernameExisting',
            'variables': {
                'username': username,
            },
            'query': 'query IsUsernameExisting($username: String!) {\n  usernameExist(username: $username)\n}\n',
        }
        return await self.session.post(url, json=json_data)

    @retry()
    @check_res_status()
    async def register_account_request(self, username):
        url = 'https://graphigo.prd.galaxy.eco/query'
        json_data = {
            'operationName': 'CreateNewAccount',
            'variables': {
                'input': {
                    'schema': f'EVM:{self.client.address}',
                    'socialUsername': username,
                    'username': username,
                },
            },
            'query': 'mutation CreateNewAccount($input: CreateNewAccount!) {\n  createNewAccount(input: $input)\n}\n',
        }
        return await self.session.post(url, json=json_data)

    async def start_galxe_registration(self):
        username = self.get_random_username()
        while True:
            username_exist = (await self.check_if_username_exist(username)).json()['data']['usernameExist']
            if not username_exist:
                break
            username = self.get_random_username()
        register_account_response = (await self.register_account_request(username)).json()
        if register_account_response['data']['createNewAccount']:
            self.logger.success(f'Galxe account registered successfully with username: {username}')
        else:
            self.logger.error(f'Something went wrong with registering new galxe account. {register_account_response}')

    async def bind_minimise(self):
        account_status = await self.check_galxe_account_info()
        for key in account_status:
            if key == 'need_add_email' and account_status[key]:
                await self.add_email()

    async def check_galxe_account_info(self):
        while True:
            try:
                check_galxe_account_info_response = (await self.check_galxe_account_info_request()).json()
                self.galxe_address_id = check_galxe_account_info_response['data']['addressInfo']['id']
                break
            except Exception:
                self.logger.error("Get galxe info error. Trying again...")
                await sleep(3, 5)
        need_add_email = False
        need_add_twitter = False
        need_add_discord = False
        if not check_galxe_account_info_response['data']['addressInfo']['hasEmail']:
            need_add_email = True
        if not check_galxe_account_info_response['data']['addressInfo']['hasTwitter']:
            need_add_twitter = True
        if not check_galxe_account_info_response['data']['addressInfo']['hasDiscord']:
            need_add_discord = True
        account_status = {'need_add_email': need_add_email,
                          'need_add_twitter': need_add_twitter,
                          'need_add_discord': need_add_discord}
        return account_status

    @retry()
    @check_res_status()
    async def check_galxe_account_info_request(self):
        url = 'https://graphigo.prd.galaxy.eco/query'
        query = (
            'query BasicUserInfo($address: String!) '
            '{\n  addressInfo(address: $address) {\n    id\n    username\n    avatar\n    address\n    '
            'evmAddressSecondary {\n      address\n      __typename\n    }\n    hasEmail\n    solanaAddress\n'
            '    aptosAddress\n    seiAddress\n    injectiveAddress\n    flowAddress\n    starknetAddress\n    '
            'bitcoinAddress\n    hasEvmAddress\n    hasSolanaAddress\n    hasAptosAddress\n    hasInjectiveAddress\n'
            '    hasFlowAddress\n    hasStarknetAddress\n    hasBitcoinAddress\n    hasTwitter\n    hasGithub\n    '
            'hasDiscord\n    hasTelegram\n    displayEmail\n    displayTwitter\n    displayGithub\n    displayDiscord\n'
            '    displayTelegram\n    displayNamePref\n    email\n    twitterUserID\n    twitterUserName\n    '
            'githubUserID\n    githubUserName\n    discordUserID\n    discordUserName\n    telegramUserID\n    '
            'telegramUserName\n    enableEmailSubs\n    subscriptions\n    isWhitelisted\n    isInvited\n    isAdmin\n'
            '    accessToken\n    __typename\n  }\n}\n'
        )
        json_data = {
            'operationName': 'BasicUserInfo',
            'variables': {
                'address': self.client.address,
            },
            'query': query,
        }
        return await self.session.post(url, json=json_data)

    @retry()
    @check_res_status()
    async def request_to_add_email(self, solution):
        url = 'https://graphigo.prd.galaxy.eco/query'
        query = (
            'mutation SendVerifyCode($input: SendVerificationEmailInput!) '
            '{\n  sendVerificationCode(input: $input) {\n    code\n    message\n    __typename\n  }\n}\n'
        )
        json_data = {
            'operationName': 'SendVerifyCode',
            'variables': {
                'input': {
                    'address': self.client.address,
                    'email': self.email.split(':')[0],
                    'captcha': {
                        'lotNumber': solution['lot_number'],
                        'captchaOutput': solution['seccode']['captcha_output'],
                        'passToken': solution['seccode']['pass_token'],
                        'genTime': solution['seccode']['gen_time'],
                    },
                },
            },
            'query': query,
        }
        return await self.session.post(url, json=json_data)

    @retry()
    @check_res_status(expected_statuses=[200, 201, 422])
    async def send_email_verif_code(self, verif_code):
        url = 'https://graphigo.prd.galaxy.eco/query'
        query = ('mutation UpdateEmail($input: UpdateEmailInput!) '
                 '{\n  updateEmail(input: $input) {\n    code\n    message\n    __typename\n  }\n}\n')
        json_data = {
            'operationName': 'UpdateEmail',
            'variables': {
                'input': {
                    'address': self.client.address,
                    'email': self.email.split(':')[0],
                    'verificationCode': verif_code,
                },
            },
            'query': query,
        }
        return await self.session.post(url, json=json_data)

    async def add_email(self):
        self.logger.info('Starting binding email...')
        _, solution = await self.captcha_solver.solve_captcha(self.logger)
        await self.request_to_add_email(solution)
        self.logger.success('Successfully sent bind email request!')
        await sleep(10, 15)
        login, pwd = self.email.split(':')
        checker = email.AsyncEmailChecker(login, pwd, logger=self.logger)

        while True:
            is_valid = await checker.check_if_email_valid()
            if not is_valid:
                self.logger.error(f"Email is invalid")
                raise Exception("Email is invalid")
            break

        for _ in range(3):
            self.logger.info(f"Waiting 15-30 seconds for galxe email code to be sent...")
            await sleep(15, 30)
            code = await checker.check_email_for_verification_link(
                pattern=r'>(\d{6})</p>',
                is_regex=True,
            )
            if not code:
                self.logger.error(f"Email code not found. Trying again...")
            else:
                self.logger.success(f"Email code found!")
                break
        else:
            self.logger.error(f"Email code not found.")
            raise Exception("Email is invalid")

        code = "".join(filter(str.isdigit, code))
        email_bind_response = (await self.send_email_verif_code(code)).json()
        if email_bind_response.get('errors'):
            self.logger.error('Something went wrong with binding email! Trying again...')
            raise Exception("Email is invalid")
        if not email_bind_response['data']['updateEmail']:
            self.logger.success('Email bound successfully!')
        else:
            self.logger.error('Email binding failed')
            raise Exception("Email is invalid")

    async def minimise_registration(self):
        if await self.is_address_registered():
            self.logger.info('Address already registered!')
            await self.bind_minimise()
        else:
            await self.start_galxe_registration()
            await self.bind_minimise()

    @retry()
    @check_res_status()
    async def get_connect_discord_data(self, captcha):
        url = 'https://graphigo.prd.galaxy.eco/query'
        json_data = {
            'operationName': 'getSocialAuthUrl',
            'variables': {
                'schema': f'EVM:{self.client.address}',
                'type': 'DISCORD',
                'captchaInput': captcha
            },
            'query': 'query getSocialAuthUrl($schema: String!, $type: SocialAccountType!, $captchaInput: CaptchaInput) {\n  getSocialAuthUrl(schema: $schema, type: $type, captchaInput: $captchaInput)\n}',
        }
        return await self.session.post(url, json=json_data)

    async def add_discord(self):
        _, solution = await self.captcha_solver.solve_captcha(self.logger)
        captcha = {'lotNumber': solution['lot_number'],
                   'captchaOutput': solution['seccode']['captcha_output'],
                   'genTime': solution['seccode']['gen_time'],
                   'passToken': solution['seccode']['pass_token']}
        connect_url = (await self.get_connect_discord_data(captcha)).json()['data']['getSocialAuthUrl']
        url = connect_url.replace(r"\u0026", "&")
        q = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
        oauth_data = {
            "client_id": q["client_id"],
            "scope": q["scope"],
            "response_type": q.get("response_type", "code"),
            "redirect_uri": q["redirect_uri"],
            "prompt": q.get("prompt", "consent"),
            "state": f"Discord_Auth,EVM:{self.client.address},false,{q['state']}",
        }
        discord_task = DiscordTask(token=self.discord_token,
                                   session=self.session,
                                   client=self.client,
                                   logger=self.logger,
                                   db_manager=self.db_manager)
        status = await discord_task.connect(oauth_data)
        if not status:
            await self.db_manager.insert_column(self.client.key, 'bad_discord_token', True)
            return False
        return True

    async def connect_discord(self):
        account_status = await self.check_galxe_account_info()
        for key in account_status:
            if key == 'need_add_discord' and account_status[key]:
                return await self.add_discord()
        return True

    @retry()
    @check_res_status()
    async def galxe_twitter_check_account(self, tweet_url):
        url = 'https://graphigo.prd.galaxy.eco/query'
        query = (
            'mutation checkTwitterAccount($input: VerifyTwitterAccountInput!) '
            '{\n  checkTwitterAccount(input: $input) {\n    address\n    twitterUserID\n    twitterUserName\n'
            '    __typename\n  }\n}\n'
        )
        json_data = {
            'operationName': 'checkTwitterAccount',
            'variables': {
                'input': {
                    'address': self.client.address,
                    'tweetURL': tweet_url,
                },
            },
            'query': query,
        }
        return await self.session.post(url, json=json_data)

    @retry()
    @check_res_status()
    async def galxe_twitter_verify_account(self, tweet_url):
        url = 'https://graphigo.prd.galaxy.eco/query'
        query = (
            'mutation VerifyTwitterAccount($input: VerifyTwitterAccountInput!) '
            '{\n  verifyTwitterAccount(input: $input) {\n    address\n    twitterUserID\n    twitterUserName\n'
            '    __typename\n  }\n}\n'
        )
        json_data = {
            'operationName': 'VerifyTwitterAccount',
            'variables': {
                'input': {
                    'address': self.client.address,
                    'tweetURL': tweet_url,
                },
            },
            'query': query,
        }
        return await self.session.post(url, json=json_data)

    async def add_twitter(self):
        twitter_task = GalxeTwitterTask(token=self.twitter_token,
                                        session=self.session,
                                        client=self.client,
                                        logger=self.logger,
                                        db_manager=self.db_manager)
        for attempt in range(1, 6):
            try:
                tweet_url = await twitter_task.connect_to_website(self.galxe_address_id)
                break
            except (BadTwitterTokenException,
                    LockedTwitterTokenException,
                    SuspendedTwitterTokenException) as e:
                self.logger.error(e)
                await self.db_manager.insert_column(self.client.key, 'bad_twitter_token', True)
                return
            except TwitterException as e:
                self.logger.error(f"{e}. Try again later. After {attempt}/5...")
                await sleep(10, 30)
        else:
            self.logger.error("Try again later.")
            return
        self.logger.success('Tweet for binding account posted successfully!')
        await self.galxe_twitter_check_account(tweet_url)
        await self.galxe_twitter_verify_account(tweet_url)
        self.logger.success('Twitter bound successfully!')
        return True

    async def connect_twitter(self):
        account_status = await self.check_galxe_account_info()
        for key in account_status:
            if key == 'need_add_twitter' and account_status[key]:
                return await self.add_twitter()
        return True

    async def galxe_login(self):
        galxe_login_response = (await self.galxe_login_request()).json()
        auth_token = galxe_login_response['data']['signin']
        self.session.headers.update({'Authorization': auth_token})
        self.logger.success('Successfully logged in!')

    @retry()
    @check_res_status()
    async def galxe_login_request(self):
        url = 'https://graphigo.prd.galaxy.eco/query'
        issued_at_str, expiration_time_str = self.get_activity_time_login()
        message_to_sign = (
            'galxe.com wants you to sign in with your Ethereum account:\n'
            f'{self.client.address}\n\n'
            'Sign in with Ethereum to the app.\n\n'
            'URI: https://galxe.com\n'
            'Version: 1\n'
            'Chain ID: 1\n'
            f'Nonce: {generate_random(17)}\n'
            f'Issued At: {issued_at_str}\n'
            f'Expiration Time: {expiration_time_str}'
        )
        json_data = {
            'operationName': 'SignIn',
            'variables': {
                'input': {
                    'address': self.client.address,
                    'message': message_to_sign,
                    'signature': self.client.get_signed_code(message_to_sign),
                    'addressType': 'EVM',
                },
            },
            'query': 'mutation SignIn($input: Auth) {\n  signin(input: $input)\n}\n',
        }
        return await self.session.post(url, json=json_data)

    @staticmethod
    def get_activity_time_login():
        issued_at = datetime.now(timezone.utc)
        expiration_time = issued_at + timedelta(days=7)
        issued_at_str = issued_at.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        expiration_time_str = expiration_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        return issued_at_str, expiration_time_str

    @retry()
    @check_res_status()
    async def check_is_guild_member(self, guild_id):
        url = 'https://graphigo.prd.galaxy.eco/query'
        json_data = {
            'operationName': 'IsGuildMember',
            'variables': {
                'guildId': guild_id,
            },
            'query': 'query IsGuildMember($guildId: String!) {\n  isGuildMember(guildId: $guildId) {\n    isGuildMember\n    failReason\n    __typename\n  }\n}',
        }
        return await self.session.post(url, json=json_data)

    async def complete_galxe_task(self, cred_id, campaign_id, with_twitter=False):
        _, solution = await self.captcha_solver.solve_captcha(self.logger)
        await self.complete_galxe_task_request(solution, cred_id, campaign_id)
        self.logger.success(f'Task {cred_id} completed successfully!')
        await sleep(10, 30)
        _, solution = await self.captcha_solver.solve_captcha(self.logger)
        verify_galxe_task_response = (await self.verify_galxe_task_request(solution,
                                                                           cred_id,
                                                                           campaign_id,
                                                                           with_twitter=with_twitter)).json()
        try:
            completed = verify_galxe_task_response['data']['syncCredentialValue']['value']['allow']
            if completed:
                self.logger.success(f'Task {cred_id} verified successfully!')
                return True
            else:
                self.logger.error(f'Task {cred_id} failed to verify! {verify_galxe_task_response}')
        except Exception:
            self.logger.error(f'Task {cred_id} failed to verify! {verify_galxe_task_response}')

    @retry()
    @check_res_status()
    async def read_survey(self, cred_id):
        url = 'https://graphigo.prd.galaxy.eco/query'
        query = 'query readSurvey($id: ID!) {\n  credential(id: $id) {\n    metadata {\n      survey {\n        ...SurveyCredMetadataFrag\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}\n\nfragment SurveyCredMetadataFrag on SurveyCredMetadata {\n  surveies {\n    title\n    type\n    items {\n      value\n      __typename\n    }\n    __typename\n  }\n  __typename\n}'
        json_data = {
            'operationName': 'readSurvey',
            'variables': {
                'id': cred_id,
            },
            'query': query
        }
        return await self.session.post(url, json=json_data)

    @retry()
    @check_res_status()
    async def verify_survey(self, cred_id, answers):
        url = 'https://graphigo.prd.galaxy.eco/query'
        query = 'mutation SyncCredentialValue($input: SyncCredentialValueInput!) {\n  syncCredentialValue(input: $input) {\n    value {\n      address\n      spaceUsers {\n        follow\n        points\n        participations\n        __typename\n      }\n      campaignReferral {\n        count\n        __typename\n      }\n      gitcoinPassport {\n        score\n        lastScoreTimestamp\n        __typename\n      }\n      walletBalance {\n        balance\n        __typename\n      }\n      multiDimension {\n        value\n        __typename\n      }\n      allow\n      survey {\n        answers\n        __typename\n      }\n      quiz {\n        allow\n        correct\n        __typename\n      }\n      __typename\n    }\n    message\n    __typename\n  }\n}'
        json_data = {
            'operationName': 'SyncCredentialValue',
            'variables': {
                'input': {
                    'syncOptions': {
                        'credId': cred_id,
                        'address': f'EVM:{self.client.address}',
                        'survey': {
                            'answers': answers,
                        },
                    },
                },
            },
            'query': query
        }
        return await self.session.post(url, json=json_data)

    @retry()
    @check_res_status()
    async def complete_conduct_request(self, cred_id, option):
        url = 'https://graphigo.prd.galaxy.eco/query'
        json_data = {
            'operationName': 'SyncCredentialValue',
            'variables': {
                'input': {
                    'syncOptions': {
                        'credId': cred_id,
                        'address': f'EVM:{self.client.address}',
                        'prediction': {
                            'option': option,
                        },
                    },
                },
            },
            'query': 'mutation SyncCredentialValue($input: SyncCredentialValueInput!) {\n  syncCredentialValue(input: $input) {\n    value {\n      address\n      spaceUsers {\n        follow\n        points\n        participations\n        __typename\n      }\n      campaignReferral {\n        count\n        __typename\n      }\n      galxePassport {\n        eligible\n        lastSelfieTimestamp\n        __typename\n      }\n      spacePoint {\n        points\n        __typename\n      }\n      spaceParticipation {\n        participations\n        __typename\n      }\n      gitcoinPassport {\n        score\n        lastScoreTimestamp\n        __typename\n      }\n      walletBalance {\n        balance\n        __typename\n      }\n      multiDimension {\n        value\n        __typename\n      }\n      allow\n      survey {\n        answers\n        __typename\n      }\n      quiz {\n        allow\n        correct\n        __typename\n      }\n      prediction {\n        isCorrect\n        __typename\n      }\n      spaceFollower {\n        follow\n        __typename\n      }\n      __typename\n    }\n    message\n    __typename\n  }\n}',
        }
        return await self.session.post(url, json=json_data)

    @retry()
    @check_res_status()
    async def read_quiz(self, cred_id):
        url = 'https://graphigo.prd.galaxy.eco/query'
        json_data = {
            'operationName': 'readQuiz',
            'variables': {
                'id': cred_id,
            },
            'query': 'query readQuiz($id: ID!) {\n  credential(id: $id) {\n    ...CredQuizFrag\n    __typename\n  }\n}\n\nfragment CredQuizFrag on Cred {\n  metadata {\n    quiz {\n      material\n      quizzes {\n        title\n        type\n        alvaHints\n        items {\n          value\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  __typename\n}',
        }
        return await self.session.post(url, json=json_data)

    @retry()
    @check_res_status()
    async def verify_quiz(self, cred_id, answers):
        url = 'https://graphigo.prd.galaxy.eco/query'
        json_data = {
            'operationName': 'SyncCredentialValue',
            'variables': {
                'input': {
                    'syncOptions': {
                        'credId': cred_id,
                        'address': f'EVM:{self.client.address}',
                        'quiz': {
                            'answers': answers
                        },
                    },
                },
            },
            'query': 'mutation SyncCredentialValue($input: SyncCredentialValueInput!) {\n  syncCredentialValue(input: $input) {\n    value {\n      address\n      spaceUsers {\n        follow\n        points\n        participations\n        __typename\n      }\n      campaignReferral {\n        count\n        __typename\n      }\n      galxePassport {\n        eligible\n        lastSelfieTimestamp\n        __typename\n      }\n      spacePoint {\n        points\n        __typename\n      }\n      spaceParticipation {\n        participations\n        __typename\n      }\n      gitcoinPassport {\n        score\n        lastScoreTimestamp\n        __typename\n      }\n      walletBalance {\n        balance\n        __typename\n      }\n      multiDimension {\n        value\n        __typename\n      }\n      allow\n      survey {\n        answers\n        __typename\n      }\n      quiz {\n        allow\n        correct\n        __typename\n      }\n      prediction {\n        isCorrect\n        __typename\n      }\n      spaceFollower {\n        follow\n        __typename\n      }\n      __typename\n    }\n    message\n    __typename\n  }\n}',
        }
        return await self.session.post(url, json=json_data)

    async def complete_quiz(self, cred_id, answers):
        await self.read_quiz(cred_id)
        await sleep(3, 5)
        quiz_response = (await self.verify_quiz(cred_id, answers)).json()
        if not quiz_response.get('errors'):
            self.logger.success(f'Quiz {cred_id} completed successfully!')
            return True
        self.logger.error(f"Quiz {cred_id} failed with errors: {quiz_response}")

    async def complete_conduct(self, cred_id, option):
        await self.read_survey(cred_id)
        await sleep(3, 5)
        conduct_response = (await self.complete_conduct_request(cred_id, option)).json()
        if not conduct_response.get('errors'):
            self.logger.success(f'Conduct {cred_id} completed successfully!')
            return True
        self.logger.error(f"Conduct {cred_id} failed with errors: {conduct_response}")

    async def complete_survey(self, cred_id, answers):
        await self.read_survey(cred_id)
        await sleep(3, 5)
        survey_response = (await self.verify_survey(cred_id, answers)).json()
        if not survey_response.get('errors'):
            self.logger.success(f'Survey {cred_id} completed successfully!')
            return True
        self.logger.error(f"Survey {cred_id} failed with errors: {survey_response}")

    @retry()
    @check_res_status()
    async def recent_campaigns(self):
        url = 'https://graphigo.prd.galaxy.eco/query'
        json_data = {
            'operationName': 'RecentParticipation',
            'variables': {
                'address': f'EVM:{self.client.address}',
                'participationInput': {
                    'first': 49,
                    'onlyGasless': False,
                    'onlyVerified': False,
                },
            },
            'query': 'query RecentParticipation($address: String!, $participationInput: ListParticipationInput!) {\n  addressInfo(address: $address) {\n    id\n    recentParticipation(input: $participationInput) {\n      list {\n        id\n        chain\n        tx\n        nftId\n        nftCore {\n          contractAddress\n          __typename\n        }\n        campaign {\n          id\n          name\n          space {\n            id\n            alias\n            __typename\n          }\n          __typename\n        }\n        status\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}',
        }
        return await self.session.post(url, json=json_data)

    @retry()
    @check_res_status()
    async def claim_completed_campaign(self, campaign_id):
        url = 'https://graphigo.prd.galaxy.eco/query'
        _, captcha = await self.captcha_solver.solve_captcha(self.logger)
        json_data = {
            'operationName': 'PrepareParticipate',
            'variables': {
                'input': {
                    'signature': '',
                    'campaignID': campaign_id,
                    'address': f'EVM:{self.client.address}',
                    'mintCount': 1,
                    'chain': 'ETHEREUM',
                    'pointMintAmount': 0,
                    'captcha': self.get_captcha_data(captcha)
                },
            },
            'query': 'mutation PrepareParticipate($input: PrepareParticipateInput!) {\n  prepareParticipate(input: $input) {\n    allow\n    disallowReason\n    signature\n    nonce\n    spaceStationInfo {\n      address\n      chain\n      version\n      __typename\n    }\n    mintFuncInfo {\n      funcName\n      nftCoreAddress\n      verifyIDs\n      powahs\n      cap\n      claimFeeAmount\n      __typename\n    }\n    extLinkResp {\n      success\n      data\n      error\n      __typename\n    }\n    metaTxResp {\n      metaSig2\n      autoTaskUrl\n      metaSpaceAddr\n      forwarderAddr\n      metaTxHash\n      reqQueueing\n      __typename\n    }\n    solanaTxResp {\n      mint\n      updateAuthority\n      explorerUrl\n      signedTx\n      verifyID\n      __typename\n    }\n    aptosTxResp {\n      signatureExpiredAt\n      tokenName\n      __typename\n    }\n    spaceStation\n    airdropRewardCampaignTxResp {\n      airdropID\n      verifyID\n      index\n      account\n      amount\n      proof\n      customReward\n      __typename\n    }\n    tokenRewardCampaignTxResp {\n      signatureExpiredAt\n      verifyID\n      encodeAddress\n      weight\n      claimFeeAmount\n      __typename\n    }\n    loyaltyPointsTxResp {\n      TotalClaimedPoints\n      VerifyIDs\n      loyaltyPointDistributionStation\n      signature\n      disallowReason\n      nonce\n      allow\n      loyaltyPointContract\n      Points\n      reqQueueing\n      claimFeeAmount\n      suiTxResp {\n        galxeTableId\n        __typename\n      }\n      __typename\n    }\n    flowTxResp {\n      Name\n      Description\n      Thumbnail\n      __typename\n    }\n    xrplLinks\n    suiTxResp {\n      packageId\n      tableId\n      nftName\n      campaignId\n      verifyID\n      imgUrl\n      signatureExpiredAt\n      __typename\n    }\n    algorandTxResp {\n      algorandArgs {\n        args\n        __typename\n      }\n      algorandBoxes {\n        boxes\n        __typename\n      }\n      __typename\n    }\n    spaceStationProxyResp {\n      target\n      callData\n      __typename\n    }\n    luckBasedTokenCampaignTxResp {\n      cid\n      dummyId\n      expiredAt\n      claimTo\n      index\n      claimAmount\n      proof\n      claimFeeAmount\n      signature\n      encodeAddress\n      weight\n      __typename\n    }\n    __typename\n  }\n}',
        }
        return await self.session.post(url, json=json_data)

    async def claim_role(self, guild_id, campaign_id):
        is_guild_member = (await self.check_is_guild_member(guild_id)).json()['data']['isGuildMember']['isGuildMember']
        if not is_guild_member:
            raise Exception("Not a guild member")
        claim_campaign_response = (await self.claim_completed_campaign(campaign_id)).json()
        if claim_campaign_response['data']['prepareParticipate']['allow']:
            self.logger.success(f"Campaign `{campaign_id}` completed successfully")
            return True
        elif 'Exceed limit, available claim count is 0' in str(claim_campaign_response):
            self.logger.info(f"Campaign `{campaign_id}` already claimed!")
            return True
        else:
            self.logger.error(f"Campaign `{campaign_id}` failed. Reason - {claim_campaign_response['data']['prepareParticipate']['disallowReason']}")

    @retry()
    @check_res_status()
    async def verify_galxe_task_request(self, captcha, cred_id, campaign_id, with_twitter=False):
        self.logger.info(f'Starting verifying {cred_id} task')
        url = 'https://graphigo.prd.galaxy.eco/query'
        query = (
            'mutation SyncCredentialValue($input: SyncCredentialValueInput!) {\n  syncCredentialValue(input: $input) '
            '{\n    value {\n      address\n      spaceUsers {\n        follow\n        points\n        '
            'participations\n        __typename\n      }\n      campaignReferral {\n        count\n        '
            '__typename\n      }\n      gitcoinPassport {\n        score\n        lastScoreTimestamp\n        '
            '__typename\n      }\n      walletBalance {\n        balance\n        __typename\n      }\n      '
            'multiDimension {\n        value\n        __typename\n      }\n      allow\n      survey {\n        '
            'answers\n        __typename\n      }\n      quiz {\n        allow\n        correct\n        __typename\n'
            '      }\n      __typename\n    }\n    message\n    __typename\n  }\n}\n'
        )
        json_data = {
            'operationName': 'SyncCredentialValue',
            'variables': {
                'input': {
                    'syncOptions': {
                        'credId': cred_id,
                        'address': f'EVM:{self.client.address}'
                    },
                },
            },
            'query': query,
        }
        if with_twitter:
            json_data['variables']['input']['syncOptions']['twitter'] = {
                'campaignID': campaign_id,
                'captcha': self.get_captcha_data(captcha)
            }
        return await self.session.post(url, json=json_data)

    @retry()
    @check_res_status()
    async def complete_galxe_task_request(self, captcha, cred_id, campaign_id):
        self.logger.info(f'Starting completing {cred_id} task')
        url = 'https://graphigo.prd.galaxy.eco/query'
        query = (
            'mutation AddTypedCredentialItems($input: MutateTypedCredItemInput!) '
            '{\n  typedCredentialItems(input: $input) {\n    id\n    __typename\n  }\n}\n'
        )
        json_data = {
            'operationName': 'AddTypedCredentialItems',
            'variables': {
                'input': {
                    'credId': cred_id,
                    'campaignId': campaign_id,
                    'operation': 'APPEND',
                    'items': [
                        f'EVM:{self.client.address}',
                    ],
                    'captcha': self.get_captcha_data(captcha)
                },
            },
            'query': query,
        }
        return await self.session.post(url, json=json_data)

    @staticmethod
    def get_captcha_data(captcha):
        return {'lotNumber': captcha['lot_number'],
                'captchaOutput': captcha['seccode']['captcha_output'],
                'passToken': captcha['seccode']['pass_token'],
                'genTime': captcha['seccode']['gen_time']}

    async def remove_socials(self):
        await self.remove_discord()
        await self.remove_twitter()

    async def remove_twitter(self):
        remove_twitter_response = (await self.remove_twitter_request()).json()
        if not remove_twitter_response.get('data', {}).get('deleteSocialAccount', True):
            self.logger.success('Twitter successfully removed!')
        else:
            self.logger.error(f"Can't remove twitter account...{remove_twitter_response}")

    async def remove_discord(self):
        remove_discord_response = (await self.remove_discord_request()).json()
        if not remove_discord_response.get('data', {}).get('deleteSocialAccount', True):
            self.logger.success('Discord successfully removed!')
        else:
            self.logger.error(f"Can't remove twitter account...{remove_discord_response}")

    @retry()
    @check_res_status()
    async def remove_twitter_request(self):
        url = 'https://graphigo.prd.galaxy.eco/query'
        query = (
            'mutation DeleteSocialAccount($input: DeleteSocialAccountInput!) {\n  deleteSocialAccount(input: $input)'
            ' {\n    code\n    message\n    __typename\n  }\n}\n'
        )
        json_data = {
            'operationName': 'DeleteSocialAccount',
            'variables': {
                'input': {
                    'address': f"EVM:{self.client.address}",
                    'type': 'TWITTER',
                },
            },
            'query': query,
        }
        return await self.session.post(url, json=json_data)

    @retry()
    @check_res_status()
    async def remove_discord_request(self):
        url = 'https://graphigo.prd.galaxy.eco/query'
        query = (
            'mutation DeleteSocialAccount($input: DeleteSocialAccountInput!) {\n  deleteSocialAccount(input: $input)'
            ' {\n    code\n    message\n    __typename\n  }\n}\n'
        )
        json_data = {
            'operationName': 'DeleteSocialAccount',
            'variables': {
                'input': {
                    'address': f"EVM:{self.client.address}",
                    'type': 'DISCORD',
                },
            },
            'query': query,
        }
        return await self.session.post(url, json=json_data)

class GalxeTask(Logger):
    def __init__(self,
                 session,
                 client,
                 twitter_token=None,
                 email=None,
                 captcha_solver: ACTUAL_CAPTCHA_SOLVER | None = None,
                 db: GalxeDb = None):
        self.session = session
        self.client = client
        self.twitter_token = twitter_token
        self.email = email
        self.captcha_solver = captcha_solver
        self.galxe_address_id = None
        self.db = db
        super().__init__(self.client.address, additional={'pk': self.client.key,
                                                          'proxy': self.session.proxies.get('http')})
        self.twitter_task = GalxeTwitterTask(twitter_token, session, client, self.logger, db)

    async def galxe_login(self):
        galxe_login_response = (await self.galxe_login_request()).json()
        auth_token = galxe_login_response['data']['signin']
        self.session.headers.update({'Authorization': auth_token})
        self.logger.success('Successfully logged in!')

    @retry()
    @check_res_status()
    async def galxe_login_request(self):
        url = 'https://graphigo.prd.galaxy.eco/query'
        issued_at_str, expiration_time_str = self.get_activity_time_login()
        message_to_sign = (
            'galxe.com wants you to sign in with your Ethereum account:\n'
            f'{self.client.address}\n\n'
            'Sign in with Ethereum to the app.\n\n'
            'URI: https://galxe.com\n'
            'Version: 1\n'
            'Chain ID: 1\n'
            f'Nonce: {generate_random(17)}\n'
            f'Issued At: {issued_at_str}\n'
            f'Expiration Time: {expiration_time_str}'
        )
        json_data = {
            'operationName': 'SignIn',
            'variables': {
                'input': {
                    'address': self.client_address,
                    'message': message_to_sign,
                    'signature': self.client.get_signed_code(message_to_sign),
                    'addressType': 'EVM',
                },
            },
            'query': 'mutation SignIn($input: Auth) {\n  signin(input: $input)\n}\n',
        }
        return await self.session.post(url, json=json_data)

    async def registration_and_binding(self):
        if await self.is_address_registered():
            self.logger.info('Address already registered!')
            await self.bind_available_socials()
        else:
            await self.start_galxe_registration()
            await self.bind_available_socials()

    async def minimise_registration(self):
        if await self.is_address_registered():
            self.logger.info('Address already registered!')
            await self.bind_minimise()
        else:
            await self.start_galxe_registration()
            await self.bind_minimise()

    async def bind_minimise(self):
        await self.db.initialise_bound_socials_table(self.client.address)
        account_status = await self.check_galxe_account_info()
        for key in account_status:
            if key == 'need_add_email' and account_status[key]:
                await self.add_email()
        galxe_account_data = (await self.check_galxe_account_info_request()).json()['data']['addressInfo']
        email = galxe_account_data.get('email')
        await self.db.bound_socials_insert_email(self.client.address, email)

    async def bind_available_socials(self):
        await self.db.initialise_bound_socials_table(self.client.address)
        while True:
            account_status = await self.check_galxe_account_info()
            for key in account_status:
                if key == 'need_add_email' and account_status[key]:
                    await self.add_email()
                elif key == 'need_add_twitter' and account_status[key]:
                    await self.bind_twitter()
            galxe_account_data = (await self.check_galxe_account_info_request()).json()['data']['addressInfo']
            email = galxe_account_data.get('email')
            galxe_twitter_username = galxe_account_data.get('twitterUserName')
            await self.db.bound_socials_insert_email(self.client.address, email)
            token_twitter_username = await self.twitter_task.get_account_username()
            if galxe_twitter_username == token_twitter_username:
                await self.db.bound_socials_insert_twitter(self.client.address, self.twitter_token, token_twitter_username)
            else:
                self.logger.error('Your twitter token username and galxe twitter username are different! '
                                  'Trying to rebind twitter...')
                await self.remove_twitter()
                continue
            break

    async def bind_twitter(self):
        tweet_url = await self.twitter_task.connect_to_website(self.galxe_address_id)
        self.logger.success('Tweet for binding account posted successfully!')
        await self.galxe_twitter_check_account(tweet_url)
        await self.galxe_twitter_verify_account(tweet_url)
        self.logger.success('Twitter bound successfully!')
        async with global_lock:
            twitter_username = await self.twitter_task.get_account_username()
            await self.db.bound_socials_insert_twitter(self.client.address,
                                                       self.twitter_token,
                                                       twitter_username)

    @retry()
    @check_res_status()
    async def galxe_twitter_check_account(self, tweet_url):
        url = 'https://graphigo.prd.galaxy.eco/query'
        query = (
            'mutation checkTwitterAccount($input: VerifyTwitterAccountInput!) '
            '{\n  checkTwitterAccount(input: $input) {\n    address\n    twitterUserID\n    twitterUserName\n'
            '    __typename\n  }\n}\n'
        )
        json_data = {
            'operationName': 'checkTwitterAccount',
            'variables': {
                'input': {
                    'address': self.client.address,
                    'tweetURL': tweet_url,
                },
            },
            'query': query,
        }
        return await self.session.post(url, json=json_data)

    @retry()
    @check_res_status()
    async def galxe_twitter_verify_account(self, tweet_url):
        url = 'https://graphigo.prd.galaxy.eco/query'
        query = (
            'mutation VerifyTwitterAccount($input: VerifyTwitterAccountInput!) '
            '{\n  verifyTwitterAccount(input: $input) {\n    address\n    twitterUserID\n    twitterUserName\n'
            '    __typename\n  }\n}\n'
        )
        json_data = {
            'operationName': 'VerifyTwitterAccount',
            'variables': {
                'input': {
                    'address': self.client.address,
                    'tweetURL': tweet_url,
                },
            },
            'query': query,
        }
        return await self.session.post(url, json=json_data)

    async def is_address_registered(self):
        is_address_registered_response = (await self.is_address_registered_request()).json()
        return is_address_registered_response["data"]["galxeIdExist"]

    @retry()
    @check_res_status()
    async def is_address_registered_request(self):
        url = 'https://graphigo.prd.galaxy.eco/query'
        self.session.headers.update({'request-id': str(uuid.uuid4())})
        json_data = {
            'operationName': 'GalxeIDExist',
            'variables': {
                'schema': f'EVM:{self.client.address}',
            },
            'query': 'query GalxeIDExist($schema: String!) {\n  galxeIdExist(schema: $schema)\n}\n',
        }
        return await self.session.post(url, json=json_data)

    async def start_galxe_registration(self):
        username = self.get_random_username()
        while True:
            username_exist = (await self.check_if_username_exist(username)).json()['data']['usernameExist']
            if not username_exist:
                break
            username = self.get_random_username()
        register_account_response = (await self.register_account_request(username)).json()
        if register_account_response['data']['createNewAccount']:
            self.logger.success(f'Galxe account registered successfully with username: {username}')
        else:
            self.logger.error(f'Something went wrong with registering new galxe account. {register_account_response}')

    async def check_galxe_account_info(self):
        check_galxe_account_info_response = (await self.check_galxe_account_info_request()).json()
        self.galxe_address_id = check_galxe_account_info_response['data']['addressInfo']['id']
        need_add_email = False
        need_add_twitter = False
        need_add_discord = False
        if not check_galxe_account_info_response['data']['addressInfo']['hasEmail']:
            need_add_email = True
        if not check_galxe_account_info_response['data']['addressInfo']['hasTwitter']:
            need_add_twitter = True
        if not check_galxe_account_info_response['data']['addressInfo']['hasDiscord']:
            need_add_discord = True
        account_status = {'need_add_email': need_add_email,
                          'need_add_twitter': need_add_twitter,
                          'need_add_discord': need_add_discord}
        self.logger.info(f'Got account status info: {account_status}')
        return account_status

    @retry()
    @check_res_status()
    async def check_galxe_account_info_request(self):
        url = 'https://graphigo.prd.galaxy.eco/query'
        query = (
            'query BasicUserInfo($address: String!) '
            '{\n  addressInfo(address: $address) {\n    id\n    username\n    avatar\n    address\n    '
            'evmAddressSecondary {\n      address\n      __typename\n    }\n    hasEmail\n    solanaAddress\n'
            '    aptosAddress\n    seiAddress\n    injectiveAddress\n    flowAddress\n    starknetAddress\n    '
            'bitcoinAddress\n    hasEvmAddress\n    hasSolanaAddress\n    hasAptosAddress\n    hasInjectiveAddress\n'
            '    hasFlowAddress\n    hasStarknetAddress\n    hasBitcoinAddress\n    hasTwitter\n    hasGithub\n    '
            'hasDiscord\n    hasTelegram\n    displayEmail\n    displayTwitter\n    displayGithub\n    displayDiscord\n'
            '    displayTelegram\n    displayNamePref\n    email\n    twitterUserID\n    twitterUserName\n    '
            'githubUserID\n    githubUserName\n    discordUserID\n    discordUserName\n    telegramUserID\n    '
            'telegramUserName\n    enableEmailSubs\n    subscriptions\n    isWhitelisted\n    isInvited\n    isAdmin\n'
            '    accessToken\n    __typename\n  }\n}\n'
        )
        json_data = {
            'operationName': 'BasicUserInfo',
            'variables': {
                'address': self.client.address,
            },
            'query': query,
        }
        return await self.session.post(url, json=json_data)

    @retry()
    @check_res_status()
    async def register_account_request(self, username):
        url = 'https://graphigo.prd.galaxy.eco/query'
        json_data = {
            'operationName': 'CreateNewAccount',
            'variables': {
                'input': {
                    'schema': f'EVM:{self.client.address}',
                    'socialUsername': '',
                    'username': username,
                },
            },
            'query': 'mutation CreateNewAccount($input: CreateNewAccount!) {\n  createNewAccount(input: $input)\n}\n',
        }
        return await self.session.post(url, json=json_data)

    @retry()
    @check_res_status()
    async def check_if_username_exist(self, username):
        url = 'https://graphigo.prd.galaxy.eco/query'
        json_data = {
            'operationName': 'IsUsernameExisting',
            'variables': {
                'username': username,
            },
            'query': 'query IsUsernameExisting($username: String!) {\n  usernameExist(username: $username)\n}\n',
        }
        return await self.session.post(url, json=json_data)

    @galxe_task_retry
    async def add_email(self):
        self.logger.info('Starting binding email...')
        _, solution = await self.captcha_solver.solve_captcha(self.logger)
        await self.request_to_add_email(solution)
        self.logger.success('Successfully sent bind email request!')
        await sleep(10, 15)
        verif_code = await EmailClient(self.email.split(':')[0], self.email.split(':')[1], self.logger).get_code()
        if verif_code is False:
            self.logger.error('Something went wrong with getting verification code! Trying again...')
            raise EmailVerificationException
        self.logger.success('Successfully got email verification code!')
        email_bind_response = (await self.send_email_verif_code(verif_code)).json()
        if email_bind_response.get('errors'):
            self.logger.error('Something went wrong with binding email! Trying again...')
            raise EmailVerificationException
        if not email_bind_response['data']['updateEmail']:
            self.logger.success('Email bound successfully!')
            await self.db.bound_socials_insert_email(self.client.address, self.email)
        else:
            self.logger.error('Email binding failed')

    @retry()
    @check_res_status(expected_statuses=[200, 201, 422])
    async def send_email_verif_code(self, verif_code):
        url = 'https://graphigo.prd.galaxy.eco/query'
        query = ('mutation UpdateEmail($input: UpdateEmailInput!) '
                 '{\n  updateEmail(input: $input) {\n    code\n    message\n    __typename\n  }\n}\n')
        json_data = {
            'operationName': 'UpdateEmail',
            'variables': {
                'input': {
                    'address': self.client.address,
                    'email': self.email.split(':')[0],
                    'verificationCode': verif_code,
                },
            },
            'query': query,
        }
        return await self.session.post(url, json=json_data)

    @retry()
    @check_res_status()
    async def request_to_add_email(self, solution):
        url = 'https://graphigo.prd.galaxy.eco/query'
        query = (
            'mutation SendVerifyCode($input: SendVerificationEmailInput!) '
            '{\n  sendVerificationCode(input: $input) {\n    code\n    message\n    __typename\n  }\n}\n'
        )
        json_data = {
            'operationName': 'SendVerifyCode',
            'variables': {
                'input': {
                    'address': self.client.address,
                    'email': self.email.split(':')[0],
                    'captcha': {
                        'lotNumber': solution['lot_number'],
                        'captchaOutput': solution['seccode']['captcha_output'],
                        'passToken': solution['seccode']['pass_token'],
                        'genTime': solution['seccode']['gen_time'],
                    },
                },
            },
            'query': query,
        }
        return await self.session.post(url, json=json_data)

    async def check_account(self, with_db=True):
        return await self.twitter_task.check_account(with_db)

    async def remove_twitter(self):
        remove_twitter_response = (await self.remove_twitter_request()).json()
        if not remove_twitter_response.get('data', {}).get('deleteSocialAccount', True):
            self.logger.success('Twitter successfully removed!')
        else:
            self.logger.error("Can't remove twitter account...")

    async def start_rebinding_twitter(self):
        account_status = await self.check_galxe_account_info()
        if not account_status['need_add_twitter']:
            remove_twitter_response = (await self.remove_twitter_request()).json()
            if not remove_twitter_response.get('data', {}).get('deleteSocialAccount', True):
                self.logger.success('Old twitter successfully removed!')
            else:
                self.logger.error("Can't remove twitter account...")
        await self.bind_twitter()

    @retry()
    @check_res_status()
    async def remove_twitter_request(self):
        url = 'https://graphigo.prd.galaxy.eco/query'
        query = (
            'mutation DeleteSocialAccount($input: DeleteSocialAccountInput!) {\n  deleteSocialAccount(input: $input)'
            ' {\n    code\n    message\n    __typename\n  }\n}\n'
        )
        json_data = {
            'operationName': 'DeleteSocialAccount',
            'variables': {
                'input': {
                    'address': self.client.address,
                    'type': 'TWITTER',
                },
            },
            'query': query,
        }
        return await self.session.post(url, json=json_data)

    @retry()
    @check_res_status()
    async def connect_aptos_wallet(self, aptos_address, aptos_public_key, nonce, message_to_sign, signature):
        url = 'https://graphigo.prd.galaxy.eco/query'
        query = 'mutation UpdateUserAddress($input: UpdateUserAddressInput!) {\n  updateUserAddress(input: $input) {\n    code\n    message\n    __typename\n  }\n}'
        json_data = {
            'operationName': 'UpdateUserAddress',
            'variables': {
                'input': {
                    'address': self.client.address,
                    'addressType': 'EVM',
                    'updateAddress': str(aptos_address),
                    'updateAddressType': 'APTOS',
                    'sig': str(signature),
                    'sigNonce': nonce,
                    'addressPublicKey': str(aptos_public_key),
                    'message': message_to_sign
                },
            },
            'query': query
        }
        return await self.session.post(url, json=json_data)

    @retry()
    @check_res_status()
    async def connect_sui_wallet(self, sui_address, nonce, message_to_sign, signature):
        url = 'https://graphigo.prd.galaxy.eco/query'
        query = 'mutation UpdateUserAddress($input: UpdateUserAddressInput!) {\n  updateUserAddress(input: $input) {\n    code\n    message\n    __typename\n  }\n}'
        json_data = {
            'operationName': 'UpdateUserAddress',
            'variables': {
                'input': {
                    'address': self.client.address,
                    'addressType': 'EVM',
                    'updateAddress': str(sui_address),
                    'updateAddressType': 'SUI',
                    'sig': str(signature),
                    'sigNonce': nonce,
                    'addressPublicKey': "",
                    'message': message_to_sign
                },
            },
            'query': query
        }
        return await self.session.post(url, json=json_data)

    @staticmethod
    def get_activity_time_login():
        issued_at = datetime.now(timezone.utc)
        expiration_time = issued_at + timedelta(days=7)
        issued_at_str = issued_at.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        expiration_time_str = expiration_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        return issued_at_str, expiration_time_str

    @staticmethod
    def get_random_request_id():
        return str(uuid.uuid4())

    @staticmethod
    def get_random_username(min_lenght=6) -> str:
        return Faker().user_name().ljust(min_lenght, str(random.randint(1, 9)))
