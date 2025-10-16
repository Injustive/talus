from utils.utils import sleep, MaxLenException
from functools import wraps


def verify_or_relogin(func):
    @wraps(func)
    async def wrapper(obj, *args, **kwargs):
        logger = obj.logger.bind(func_name=func.__name__, func_module=func.__module__)
        try:
            while True:
                response = await func(obj, *args, **kwargs)
                if response.status_code == 429 and 'Too many requests' in response.text:
                    obj.logger.info("Too many requests. Trying again later...")
                    await sleep(30, 60)
                    continue
                return response
        except MaxLenException:
            logger.info("Cloudflare found. Trying relogin...")
            await obj.login()
            return await func(obj, *args, **kwargs)
    return wrapper