from utils.client import Client
from utils.utils import (retry, check_res_status, get_utc_now,
                         get_data_lines, sleep, Logger,
                         read_json, Contract, read_json,
                         approve_asset, asset_balance, get_decimals,
                         approve_if_insufficient_allowance,
                         generate_random, BadTwitterTokenException, LockedTwitterTokenException,
                         SuspendedTwitterTokenException, TwitterException)
from utils.models import RpcProviders, TxStatusResponse
from .config import *
import copy
from datetime import datetime, timezone, timedelta
from utils.email import email
from utils.galxe_utils.captcha import CapmonsterSolver
import base64
from utils.client import SolanaClient, SuiClient
from .twitter_task import TwitterTask
from .paths import *
from .discord_task import DiscordTask
import random
from .utils import verify_or_relogin
from functools import partial


class Task(Logger):
    def __init__(self, session, client: Client, db_manager,
                 twitter_token:str, discord_token:str, email:str,
                 sol_wallet: str, sui_wallet: str):
        self.session = session
        self.client = client
        self.db_manager = db_manager
        self.twitter_token = twitter_token
        self.discord_token = discord_token
        self.email = email
        self.sol_wallet = sol_wallet
        self.sui_wallet = sui_wallet
        super().__init__(self.client.address, additional={'pk': self.client.key,
                                                          'proxy': self.session.proxies.get('http')})
        self.initial_headers = copy.deepcopy(self.session.headers)
        self.captcha_solver = CapmonsterSolver(session=self.session,
                                               api_key=CAPTCHA_API_KEY,
                                               logger=self.logger)
        self.user_id = None
        self.sol_client = None
        self.sui_client = None
        self.nonce = None
        self.twitter_task = TwitterTask(token=self.twitter_token,
                                        session=self.session,
                                        client=self.client,
                                        logger=self.logger,
                                        db_manager=self.db_manager)
        self.discord_task = DiscordTask(token=self.discord_token,
                                        session=self.session,
                                        client=self.client,
                                        logger=self.logger,
                                        db_manager=self.db_manager)

    @retry()
    @check_res_status(expected_statuses=[200, 201])
    @verify_or_relogin
    async def get_csrf(self):
        url = 'https://hub.talus.network/api/auth/csrf'
        return await self.session.get(url)

    async def solve_cloudflare(self):
        url = 'https://hub.talus.network/loyalty'
        cloudflare_response = (await self.session.get(url)).text
        encoded_bytes = base64.b64encode(cloudflare_response.encode("utf-8"))
        encoded_text = encoded_bytes.decode("utf-8")
        cf_clearance = await self.captcha_solver.solve_turnstile_cookies(url='https://hub.talus.network/loyalty',
                                                                         key='0x4AAAAAAADnPIDROrmt1Wwj',
                                                                         cloudflare_response_base64=encoded_text,
                                                                         user_agent=self.session.headers.get('user-agent'))
        self.session.cookies.update({'cf_clearance': cf_clearance['cf_clearance']})

    @staticmethod
    def seconds_until_next_day(min_delay, max_delay):
        now = datetime.now(timezone.utc)
        next_day = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        seconds_left = (next_day - now).total_seconds()
        random_delay = random.randint(min_delay, max_delay)
        return int(seconds_left + random_delay)

    async def login(self):
        self.session.headers = self.initial_headers
        self.session.cookies = {}
        current_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        await self.solve_cloudflare()
        self.nonce = (await self.get_csrf()).json()['csrfToken']
        login_response = await self.login_request(self.nonce, current_time)
        login_session_token = login_response.cookies.get("__Secure-next-auth.session-token")
        login_response = login_response.json()
        if login_session_token and login_response.get('url'):
            self.logger.success('Login successful!')
        else:
            self.logger.error(f'Login failed! {login_response}')
        user_info = (await self.get_user_info()).json()["data"][0]
        self.user_id = user_info["id"]
        self.sol_client = SolanaClient(seed=self.sol_wallet)
        self.sui_client = SuiClient(seed=self.sui_wallet)
        await self.sol_client.init()
        await self.sui_client.init()

    @retry()
    @check_res_status()
    @verify_or_relogin
    async def login_request(self, csrf, current_time):
        url = 'https://hub.talus.network/api/auth/callback/credentials'
        message_to_sign = (
            "hub.talus.network wants you to sign in with your Ethereum account:\n"
            f"{self.client.address}\n\n"
            "Sign in to the app. Powered by Snag Solutions.\n\n"
            "URI: https://hub.talus.network\n"
            "Version: 1\n"
            f"Chain ID: 1\n"
            f"Nonce: {csrf}\n"
            f"Issued At: {current_time}"
        )
        data = {
            "message": '{"domain":"hub.talus.network","address":"'
                       + self.client.address
                       + '","statement":"Sign in to the app. Powered by Snag Solutions.","uri":"https://hub.talus.network","version":"1","chainId":1,"nonce":"'
                       + csrf
                       + '","issuedAt":"'
                       + current_time
                       + '"}',
            "accessToken": self.client.get_signed_code(message_to_sign),
            "signature": self.client.get_signed_code(message_to_sign),
            "walletConnectorName": "Rabby",
            "walletAddress": self.client.address,
            "redirect": "false",
            "callbackUrl": "/protected",
            "chainType": "evm",
            'walletProvider': 'undefined',
            "csrfToken": csrf,
            "json": "true",
        }
        return await self.session.post(url, data=data)

    @retry()
    @check_res_status()
    @verify_or_relogin
    async def send_code_request(self, login):
        url = f'https://hub.talus.network/api/users/{self.user_id}'
        json_data = {
            'emailAddress': login,
        }
        return await self.session.post(url, json=json_data)

    @retry()
    @check_res_status()
    @verify_or_relogin
    async def get_user_info(self):
        url = 'https://hub.talus.network/api/users'
        params = {
            'includeDelegation': 'true',
            'walletAddress': self.client.address,
            'websiteId': '9b193878-a015-4450-b1a3-a7726d2cbf6d',
            'organizationId': '842777eb-3017-49ed-8081-27f672133789',
        }
        return await self.session.get(url, params=params)

    async def connect_email(self):
        if not self.email:
            self.logger.error("Not found email for this account. Add email")
            return

        login = self.email.split(":")[0]
        pwd = self.email.split(":")[1]

        checker = email.AsyncEmailChecker(login, pwd, logger=self.logger)

        while True:
            is_valid = await checker.check_if_email_valid()
            if not is_valid:
                self.logger.error(f"Email is invalid. Trying to change...")
                replace_status = await self.replace_email()
                if replace_status:
                    continue
                self.logger.error("Need to add extra emails first")
                await self.db_manager.insert_column(self.client.key, 'bad_email', True)
                return False
            send_code_response = (await self.send_code_request(login)).json()
            if send_code_response.get("success"):
                self.logger.success("Send code successfully!")

            for _ in range(3):
                self.logger.info(f"Waiting 15-30 seconds for talus email code to be sent...")
                await sleep(15, 30)
                url = await checker.check_email_for_verification_link(
                    pattern=r'a href="(.+)" style',
                    is_regex=True,
                )
                if not url:
                    self.logger.error(f"Email code not found. Trying again...")
                else:
                    self.logger.success(f"Email code found!")
                    break
            else:
                self.logger.error(f"Email code not found.")
                replace_status = await self.replace_email()
                if replace_status:
                    continue
                self.logger.error("Need to add extra emails first")
                await self.db_manager.insert_column(self.client.key, 'bad_email', True)
                return False
            url = url.replace('a href="', '').replace('" style', "")
            await self.session.get(url)
            self.logger.success(f"Email connected successfully!")
            await self.db_manager.insert_column(self.client.key, 'email_connected', True)
            return True

    @retry()
    @check_res_status(expected_statuses=[200, 201, 400])
    @verify_or_relogin
    async def connect_sol_wallet_request(self):
        url = 'https://hub.talus.network/api/users/connect'
        issued_at = get_utc_now()
        msg_to_sign_data = ('{"header":{"t":"sip99"},"payload":{"domain":"hub.talus.network","address":'
                       f'"{self.sol_client.address}","statement":"Sign in to the app. Powered by Snag Solutions.","uri":"https://snag-web.onrender.com","version":"1","chainId":101,'
                       f'"nonce":"{self.nonce}","issuedAt":"{issued_at}",'
                       '"chainType":"solana"}}')
        msg_to_sign = (
            "hub.talus.network wants you to sign in with your Solana account:\n"
            f"{self.sol_client.address}\n\n"
            "Sign in to the app. Powered by Snag Solutions.\n\n"
            "URI: https://snag-web.onrender.com\n"
            "Version: 1\n"
            f"Chain ID: 101\n"
            f"Nonce: {self.nonce}\n"
            f"Issued At: {issued_at}"
        )
        json_data = {
            'websiteId': '9b193878-a015-4450-b1a3-a7726d2cbf6d',
            'organizationId': '842777eb-3017-49ed-8081-27f672133789',
            'walletType': 'solana',
            'walletAddress': self.sol_client.address,
            'verificationData': {
                'signature': await self.sol_client.sign_message(message=msg_to_sign, encoding='base64'),
                'walletAddress': self.sol_client.address,
                'walletType': 'solana',
                'message': msg_to_sign_data,
            },
        }
        return await self.session.post(url, json=json_data)

    async def connect_sol_wallet(self):
        connect_solana_response = await self.connect_sol_wallet_request()
        if connect_solana_response.status_code in [200, 201]:
            self.logger.success("Solana wallet connected successfully!")
            return True
        elif 'CONFLICTING_METADATA' in connect_solana_response.text:
            self.logger.error(f"Sui wallet not connected. Maybe this wallet connected to another account")
        else:
            self.logger.error(f"Solana wallet not connected: {connect_solana_response.text}")

    @retry()
    @check_res_status(expected_statuses=[200, 201, 400])
    @verify_or_relogin
    async def connect_sui_wallet_request(self):
        url = 'https://hub.talus.network/api/users/connect'
        msg_to_sign = ('{"domain":"hub.talus.network","statement":"Sign in to the app. Powered by Snag Solutions.","uri":"https://snag-web.onrender.com","chainType":"sui","version":"1","chainId":0,'
                       f'"nonce":"{self.nonce}","address":"{self.sui_client.address}"'
                       '}')
        json_data = {
            'websiteId': '9b193878-a015-4450-b1a3-a7726d2cbf6d',
            'organizationId': '842777eb-3017-49ed-8081-27f672133789',
            'walletType': 'sui',
            'walletAddress': self.sui_client.address,
            'verificationData': {
                'signature': await self.sui_client.sign_message(message=msg_to_sign),
                'walletAddress': '0x9453655bddfbc90432dd98c0e2e6e3ae4f3ba0a7d337f284ed4c1bd6e8c8d77e',
                'walletType': 'sui',
                'message': msg_to_sign,
            },
        }
        return await self.session.post(url, json=json_data)

    async def connect_sui_wallet(self):
        connect_sui_response = await self.connect_sui_wallet_request()
        if connect_sui_response.status_code in [200, 201]:
            self.logger.success("Sui wallet connected successfully!")
            return True
        elif 'CONFLICTING_METADATA' in connect_sui_response.text:
            self.logger.error(f"Sui wallet not connected. Maybe this wallet connected to another account")
        else:
            self.logger.error(f"Sui wallet not connected: {connect_sui_response.text}")

    @staticmethod
    def replace_bad_banned_twitter_tokens_file(bad, new):
        all_tokens = list(get_data_lines(TWITTER_TOKENS))
        new_tokens = [new if token == bad else token for token in all_tokens]
        with open(TWITTER_TOKENS, 'w') as file:
            for line in new_tokens:
                file.write(line + '\n')

    @staticmethod
    def delete_twitter_token(code_to_delete):
        tokens = list(i for i in get_data_lines(EXTRA_TWITTER_TOKENS) if i)
        with open(EXTRA_TWITTER_TOKENS, 'w') as file:
            for token in tokens:
                if token != code_to_delete:
                    file.write(token + '\n')

    @staticmethod
    def replace_bad_banned_emails_file(bad, new):
        all_tokens = list(get_data_lines(EMAILS))
        new_tokens = [new if token == bad else token for token in all_tokens]
        with open(EMAILS, 'w') as file:
            for line in new_tokens:
                file.write(line + '\n')

    @staticmethod
    def delete_email(email):
        tokens = list(i for i in get_data_lines(EXTRA_EMAILS) if i)
        with open(EXTRA_EMAILS, 'w') as file:
            for token in tokens:
                if token != email:
                    file.write(token + '\n')

    @staticmethod
    def replace_bad_banned_discord_tokens_file(bad, new):
        all_tokens = list(get_data_lines(DISCORD_TOKENS))
        new_tokens = [new if token == bad else token for token in all_tokens]
        with open(DISCORD_TOKENS, 'w') as file:
            for line in new_tokens:
                file.write(line + '\n')

    @staticmethod
    def delete_discord_token(code_to_delete):
        tokens = list(i for i in get_data_lines(EXTRA_DISCORD_TOKENS) if i)
        with open(EXTRA_DISCORD_TOKENS, 'w') as file:
            for token in tokens:
                if token != code_to_delete:
                    file.write(token + '\n')

    async def replace_email(self):
        self.logger.info("Starting replacing email...")
        while True:
            extra_emails = list(get_data_lines(EXTRA_EMAILS))
            new_email = random.choice(extra_emails) if extra_emails else None
            if not new_email:
                self.logger.error("New emails not found!")
                return False
            self.replace_bad_banned_emails_file(self.email, new_email)
            self.delete_email(new_email)
            await self.db_manager.insert_column(self.client.key, 'email', new_email)
            self.email = new_email
            self.logger.success(f"Email replaced successfully! Got new email - {new_email}")
            await self.db_manager.insert_column(self.client.key, 'bad_email', False)
            return True

    @retry()
    @check_res_status()
    @verify_or_relogin
    async def disconnect_twitter_request(self):
        url = 'https://hub.talus.network/api/twitter/auth/disconnect'
        return await self.session.post(url)

    async def replace_twitter(self):
        self.logger.info("Starting replacing twitter...")
        while True:
            new_twitter_tokens = list(get_data_lines(EXTRA_TWITTER_TOKENS))
            if not new_twitter_tokens:
                self.logger.error("New twitter tokens not found!")
                return False
            new_twitter_token = random.choice(new_twitter_tokens)
            self.replace_bad_banned_twitter_tokens_file(self.twitter_task.token, new_twitter_token)
            self.delete_twitter_token(new_twitter_token)
            await self.db_manager.insert_column(self.client.key, 'twitter_token', new_twitter_token)
            self.twitter_task.update_token(new_twitter_token)
            await self.db_manager.insert_column(self.client.key, 'bad_twitter_token', False)
            return True

    async def replace_discord(self):
        self.logger.info("Starting replacing discord...")
        while True:
            new_discord_tokens = list(get_data_lines(EXTRA_DISCORD_TOKENS))
            if not new_discord_tokens:
                self.logger.error("New discord tokens not found!")
                return False
            new_discord_token = random.choice(new_discord_tokens)
            self.replace_bad_banned_discord_tokens_file(self.twitter_task.token, new_discord_token)
            self.delete_discord_token(new_discord_token)
            await self.db_manager.insert_column(self.client.key, 'discord_token', new_discord_token)
            self.discord_task.update_token(new_discord_token)
            await self.db_manager.insert_column(self.client.key, 'bad_discord_token', False)
            return True

    async def connect_twitter(self):
        while True:
            try:
                await self.twitter_task.connect()
                return True
            except (BadTwitterTokenException,
                    LockedTwitterTokenException,
                    SuspendedTwitterTokenException) as e:
                self.logger.error(e)
                await self.db_manager.insert_column(self.client.key, 'bad_twitter_token', True)
                status = await self.replace_twitter()
                if not status:
                    return False
                continue
            except TwitterException as e:
                self.logger.error(f"{e}. Try again later.")
                await sleep(10, 30)
                continue

    async def connect_discord(self):
        while True:
            if await self.db_manager.get_column(self.client.key, 'discord_connected'):
                self.logger.info("Discord already connected!")
                return True
            if not self.discord_task.token:
                self.logger.info("You don't have discord token. Add first to connect.")
                return
            connect_status = await self.discord_task.connect()
            if not connect_status:
                await self.db_manager.insert_column(self.client.key, 'bad_discord_token', True)
                status = await self.replace_discord()
                if not status:
                    return False
                continue
            return True

    async def complete_initial_tasks(self):
        email_status = await self.connect_email()
        sol_status = await self.connect_sol_wallet()
        sui_status = await self.connect_sui_wallet()
        connect_twitter_status = await self.connect_twitter()
        if not connect_twitter_status:
            self.logger.error("Need to add extra twitters first")
            return
        else:
            await self.db_manager.insert_column(self.client.key, 'twitter_connected', True)
            self.logger.success("Twitter connected successfully!")
        connect_discord_status = await self.connect_discord()
        if not connect_discord_status:
            self.logger.error("Need to add extra discords first")
            return
        else:
            await self.db_manager.insert_column(self.client.key, 'discord_connected', True)
            self.logger.success("Discord connected successfully!")
        if (email_status and sol_status and sui_status
            and await self.db_manager.get_column(self.client.key, 'discord_connected')
                and await self.db_manager.get_column(self.client.key, 'twitter_connected')):
            await self.db_manager.insert_column(self.client.key, 'initials_tasks_completed', True)

    @retry()
    @check_res_status()
    @verify_or_relogin
    async def get_all_quests(self):
        url = 'https://hub.talus.network/api/loyalty/rule_groups'
        params = {
            'limit': '20',
            'websiteId': '9b193878-a015-4450-b1a3-a7726d2cbf6d',
            'organizationId': '842777eb-3017-49ed-8081-27f672133789',
            'isActive': 'true',
        }
        return await self.session.get(url, params=params)

    @retry()
    @check_res_status()
    @verify_or_relogin
    async def get_completed_tasks(self):
        url = 'https://hub.talus.network/api/loyalty/transaction_entries'
        params = {
            'limit': '50',
            'orderBy': 'createdAt',
            'websiteId': '9b193878-a015-4450-b1a3-a7726d2cbf6d',
            'userId': self.user_id,
            'organizationId': '842777eb-3017-49ed-8081-27f672133789',
            'loyaltyCurrencyId': [
                '4eae8c51-a8c9-4214-b409-2418d933b5b9',
                '73a8a439-250e-49d0-af15-be4fc8a9f856',
            ],
            'hideFailedMints': 'true',
        }
        return await self.session.get(url, params=params)

    @retry()
    @check_res_status()
    @verify_or_relogin
    async def complete_daily_post_twitter(self, tw_url):
        url = 'https://hub.talus.network/api/loyalty/rules/f4497591-da67-4bba-a0d7-213a61648cdf/complete'
        json_data = {
            'contentUrl': tw_url
        }
        return await self.session.post(url, json=json_data)

    @retry()
    @check_res_status()
    @verify_or_relogin
    async def wait_for_quest_completion_request(self):
        url = 'https://hub.talus.network/api/loyalty/rules/status'
        params = {
            'websiteId': '9b193878-a015-4450-b1a3-a7726d2cbf6d',
            'organizationId': '842777eb-3017-49ed-8081-27f672133789',
            'userId': self.user_id
        }
        return await self.session.get(url, params=params)

    async def wait_for_quest_completion(self, quest):
        for attempt in range(1, 21):
            try:
                await sleep(*SLEEP_BETWEEN_TASKS)
                quest_completion_response = (await self.wait_for_quest_completion_request()).json()['data']
                for completion_quest in quest_completion_response:
                    if completion_quest['loyaltyRuleId'] != quest['loyaltyRule']['id']:
                        continue
                    if 'Quest already completed' in str(completion_quest):
                        self.logger.info(f"Quest {quest['loyaltyRule']['name']} already completed")
                        return True
                    if completion_quest["status"] == "processing" or completion_quest["status"] == "pending":
                        self.logger.info(f"Quest {quest['loyaltyRule']['name']} is being processed...{attempt}/20...")
                        continue
                    elif completion_quest["status"] == "completed":
                        self.logger.success(f"Quest {quest['loyaltyRule']['name']} completed successfully!")
                        return True
                else:
                    self.logger.error(f"Failed to verify quest completion: {completion_quest}")
                    return False
            except Exception as e:
                self.logger.error(f"Quest completion failed: {e}. "
                                  f"Response: {completion_quest}. Attempts {attempt}/20...")
                continue

    @retry()
    @check_res_status(expected_statuses=[200, 201, 400])
    @verify_or_relogin
    async def complete_quest_request(self, quest_id, payload):
        url = f'https://hub.talus.network/api/loyalty/rules/{quest_id}/complete'
        return await self.session.post(url, json=payload)

    async def complete_quest(self, quest, payload=None):
        if not payload:
            payload = {}
        complete_quest_response = await self.complete_quest_request(quest['loyaltyRule']['id'], payload=payload)
        if 'You have already been rewarded' in complete_quest_response.text or "You already checked in" in complete_quest_response.text:
            self.logger.info(f"Task {quest['loyaltyRule']['name']} already completed!")
            return True
        complete_quest_response = complete_quest_response.json()
        if "Completion request added to queue" in str(complete_quest_response) or "Link click being verified" in str(complete_quest_response):
            self.logger.info(f"Quest {quest['loyaltyRule']['name']} added to queue successfully. Waiting for completion...")
            return await self.wait_for_quest_completion(quest)

    async def complete_twitter_task(self, task):
        while True:
            try:
                return await task()
            except (BadTwitterTokenException,
                    LockedTwitterTokenException,
                    SuspendedTwitterTokenException) as e:
                self.logger.error(f'{e}. Need to change twitter!')
                await self.db_manager.insert_column(self.client.key, 'bad_twitter_token', True)
                return False
            except TwitterException as e:
                await sleep(*SLEEP_BETWEEN_TASKS)
                self.logger.error(f"{e}. Wait some time and try again.")
                continue

    async def complete_other_tasks(self):
        TASKS_MAP = {
            "f4497591-da67-4bba-a0d7-213a61648cdf": partial(self.twitter_task.quote_post,
                                                            "Talus labs"),
            "3c1b0c4f-060f-4be4-a7cb-8bef9ed60cf6": partial(self.twitter_task.complete_follow_task,
                                                            "@SuiNetwork"),
            "8da0d449-5b7a-4103-9510-6919cdedee0f": partial(self.twitter_task.complete_follow_task,
                                                            "@WalrusProtocol"),
            "af8b6614-e7a6-435b-8e96-5ff1e0b8e678": partial(self.twitter_task.complete_follow_task,
                                                            "@CetusProtocol"),
            "ebc12469-c9a8-4487-9691-9feaf8125449": partial(self.twitter_task.complete_follow_task,
                                                            "@navi_protocol"),
            "3bd1524a-1854-4125-aae5-4e1352ca768d": partial(self.twitter_task.complete_follow_task,
                                                            "@tradeportxyz"),
            "085a9d6e-52fc-44d1-861d-b8ae514a2090": partial(self.twitter_task.complete_follow_task,
                                                            "@SuiNSdapp"),
            "b7b01971-ef84-479b-8d96-aa3b3f13749e": partial(self.twitter_task.complete_follow_task,
                                                            "@AftermathFi"),
            "4f85627a-5ed5-45f8-9334-47b17c8c3079": partial(self.twitter_task.complete_follow_task,
                                                            "@suilendprotocol")
        }

        all_quests = (await self.get_all_quests()).json()['data']
        onboarding_quests = [quest for quest in all_quests if quest['name'] == 'Onboarding'][0]['loyaltyGroupItems']
        daily_quests = [quest for quest in all_quests if quest['name'] == 'Daily Missions'][0]['loyaltyGroupItems']
        completed_tasks = (await self.get_completed_tasks()).json()['data']
        completed_ids = [quest['loyaltyTransaction']['loyaltyRule']['id'] for quest in completed_tasks]
        required_onboarding = ['6684605a-1675-46ef-a60f-d825927af3e9', '91991ad1-5db7-4ced-ad81-b7ada09b3d6d', '6eb6a7df-79e1-45f7-bc82-55c9f468b5ef', '9621ba2f-fa77-4f8d-9182-f1e5a127a4da', 'c715daaa-986f-4a00-ad3c-743559713ff3']

        random.shuffle(onboarding_quests)
        for quest in onboarding_quests:
            if quest['loyaltyRule']['id'] not in completed_ids:
                await self.complete_quest(quest)

        if all(required in completed_ids for required in required_onboarding):
            self.logger.success(f'All required tasks completed successfully!')
        else:
            self.logger.error("You need to complete all required tasks first!")
            return

        daily_quests_ids = ["f4497591-da67-4bba-a0d7-213a61648cdf", "26951d0b-1ade-4d99-a174-7e056f0952b3",
                            "de4146bf-6718-43a3-8212-a487d2ffda3a", "d02d47f4-6f01-43db-adab-7cb4ae805557",
                            "9ddf77b9-3db1-4132-b077-b02a7b8ac516"]
        random.shuffle(daily_quests)
        for quest in daily_quests:
            if quest['loyaltyRule']['id'] in daily_quests_ids:
                if quest['loyaltyRule']['id'] == "f4497591-da67-4bba-a0d7-213a61648cdf":
                    task_quest = TASKS_MAP.get(quest['loyaltyRule']['id'])
                    if task_quest:
                        quote_id = await self.complete_twitter_task(task_quest)
                        if quote_id:
                            twitter_username = self.twitter_task.account.username
                            twitter_url = f"https://x.com/{twitter_username}/status/{quote_id}"
                            await self.complete_quest(quest, payload={"contentUrl": twitter_url})
                else:
                    print(quest)
                    await self.complete_quest(quest)

        twitter_tasks = [quest for quest in all_quests if quest['name'] == 'Follow Us!'][0]['loyaltyGroupItems']
        random.shuffle(twitter_tasks)
        if (not await self.db_manager.get_column(self.client.key, 'bad_twitter_token')
                and await self.db_manager.get_column(self.client.key, 'twitter_connected')):
            for quest in twitter_tasks:
                if quest['loyaltyRule']['id'] not in completed_ids:
                    task_quest = TASKS_MAP.get(quest['loyaltyRule']['id'])
                    if task_quest:
                        status = await self.complete_twitter_task(task_quest)
                        if status:
                            await self.complete_quest(quest)
                        await sleep(*SLEEP_BETWEEN_TASKS)

    async def start(self):
        while True:
            await self.login()
            if not await self.db_manager.get_column(self.client.key, 'initials_tasks_completed'):
                await self.complete_initial_tasks()
            await self.complete_other_tasks()
            random_sleep_daily_time = self.seconds_until_next_day(*SLEEP_FROM_TO)
            self.logger.info(f"Sleeping for {random_sleep_daily_time}s before next day...")
            await sleep(random_sleep_daily_time)
