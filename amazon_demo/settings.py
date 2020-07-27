# -*- coding: utf-8 -*-

# Scrapy settings for amazon_demo project
#
# For simplicity, this file contains only settings considered important or
# commonly used. You can find more settings consulting the documentation:
#
#     https://doc.scrapy.org/en/latest/topics/settings.html
#     https://doc.scrapy.org/en/latest/topics/downloader-middleware.html
#     https://doc.scrapy.org/en/latest/topics/spider-middleware.html

import os
import sys
import redis
from dotenv import load_dotenv

dotenv_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env')
if os.path.isfile(dotenv_path):
  load_dotenv(dotenv_path=dotenv_path)

BOT_NAME = 'amazon_demo'

SPIDER_MODULES = ['amazon_demo.spiders']
NEWSPIDER_MODULE = 'amazon_demo.spiders'


# Crawl responsibly by identifying yourself (and your website) on the user-agent
#USER_AGENT = 'amazon_demo (+http://www.yourdomain.com)'

# Obey robots.txt rules
ROBOTSTXT_OBEY = False

# Configure maximum concurrent requests performed by Scrapy (default: 16)
CONCURRENT_REQUESTS = 8

# Configure a delay for requests for the same website (default: 0)
# See https://doc.scrapy.org/en/latest/topics/settings.html#download-delay
# See also autothrottle settings and docs
DOWNLOAD_DELAY = 0
# The download delay setting will honor only one of:
#CONCURRENT_REQUESTS_PER_DOMAIN = 16
CONCURRENT_REQUESTS_PER_IP = 8

# Disable cookies (enabled by default)
COOKIES_ENABLED = True
COOKIES_DEBUG = False

# Disable Telnet Console (enabled by default)
#TELNETCONSOLE_ENABLED = False

# Override the default request headers:
DEFAULT_REQUEST_HEADERS = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US',
    'Referer': 'https://www.amazon.com'
}

# Enable or disable spider middlewares
# See https://doc.scrapy.org/en/latest/topics/spider-middleware.html
#SPIDER_MIDDLEWARES = {
#    'amazon_demo.middlewares.AmazonUsDemoSpiderMiddleware': 543,
#}

# Enable or disable downloader middlewares
# See https://doc.scrapy.org/en/latest/topics/downloader-middleware.html
DOWNLOADER_MIDDLEWARES = {
    'scrapy.downloadermiddlewares.useragent.UserAgentMiddleware': 400,
    # 'scrapy_user_agents.middlewares.RandomUserAgentMiddleware': 400,
    'scrapy.downloadermiddlewares.retry.RetryMiddleware': 410,
    'amazon_demo.middlewares.AmazonCaptchaResolverMiddleware': 450,
    'scrapy_proxy_pool.middlewares.ProxyPoolMiddleware': 610,
    'scrapy_proxy_pool.middlewares.BanDetectionMiddleware': 620,
    'scrapy.downloadermiddlewares.httpcompression.HttpCompressionMiddleware': 810,
}

# Enable or disable extensions
# See https://doc.scrapy.org/en/latest/topics/extensions.html
#EXTENSIONS = {
#    'scrapy.extensions.telnet.TelnetConsole': None,
#}

# Configure item pipelines
# See https://doc.scrapy.org/en/latest/topics/item-pipeline.html
# ITEM_PIPELINES = {
# }

# Enable and configure the AutoThrottle extension (disabled by default)
# See https://doc.scrapy.org/en/latest/topics/autothrottle.html
AUTOTHROTTLE_ENABLED = False
# The initial download delay
AUTOTHROTTLE_START_DELAY = 0.33
# The maximum download delay to be set in case of high latencies
AUTOTHROTTLE_MAX_DELAY = 60
# The average number of requests Scrapy should be sending in parallel to
# each remote server
AUTOTHROTTLE_TARGET_CONCURRENCY = 3.0
# Enable showing throttling stats for every response received:
AUTOTHROTTLE_DEBUG = False

# Enable and configure HTTP caching (disabled by default)
# See https://doc.scrapy.org/en/latest/topics/downloader-middleware.html#httpcache-middleware-settings
#HTTPCACHE_ENABLED = True
#HTTPCACHE_EXPIRATION_SECS = 0
#HTTPCACHE_DIR = 'httpcache'
#HTTPCACHE_IGNORE_HTTP_CODES = []
#HTTPCACHE_STORAGE = 'scrapy.extensions.httpcache.FilesystemCacheStorage'

# RetryMiddleware settings
RETRY_ENABLED = True
RETRY_TIMES = 5
RETRY_HTTP_CODES = [500, 503, 408, 400]

# User agent settings
RANDOM_UA_TYPE = 'desktop.random'
RANDOM_UA_FALLBACK = 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.87 Safari/537.36'
RANDOM_UA_SAME_OS_FAMILY = True


# Amazon captcha resolver settings
AMAZON_CAPTCHA_RESOLVER_ENABLED = True
AMAZON_CAPTCHA_RESOLVER_USERNAME = os.getenv('AMAZON_CAPTCHA_RESOLVER_USERNAME', '')
AMAZON_CAPTCHA_RESOLVER_PASSWORD = os.getenv('AMAZON_CAPTCHA_RESOLVER_PASSWORD', '')
AMAZON_CAPTCHA_RESOLVER_THRESHOLD = os.getenv('AMAZON_CAPTCHA_RESOLVER_THRESHOLD', 32)
AMAZON_CAPTCHA_WAIT_TIME = os.getenv('AMAZON_CAPTCHA_WAIT_TIME', 0)
AMAZON_CAPTCHA_RESOLVE_RATE = os.getenv('AMAZON_CAPTCHA_RESOLVE_RATE', 1)

# ElasticSearchPipline settings
ELASTICSEARCH_SERVERS = os.getenv('ELASTICSEARCH_SERVERS', '127.0.0.1')
ELASTICSEARCH_INDEX = os.getenv('ELASTICSEARCH_INDEX', 'amazon_demo')
ELASTICSEARCH_USERNAME = os.getenv('ELASTICSEARCH_USERNAME', '')
ELASTICSEARCH_PASSWORD = os.getenv('ELASTICSEARCH_PASSWORD', '')
ELASTICSEARCH_ID_KEY = os.getenv('ELASTICSEARCH_ID_KEY', 'asin')
ELASTICSEARCH_TIMEOUT = int(os.getenv('ELASTICSEARCH_TIMEOUT', 60))
ELASTICSEARCH_MAX_RETRY = int(os.getenv('ELASTICSEARCH_MAX_RETRY', 3))
ELASTICSEARCH_BUFFER_LENGTH = int(os.getenv('ELASTICSEARCH_BUFFER_LENGTH', 500))

# scrapy-redis settings
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379')
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
REDIS_CLS = redis.Redis
REDIS_PARAMS  = {}

REDIS_START_URLS_BATCH_SIZE = sys.maxint if hasattr(sys, 'maxint') else sys.maxsize
REDIS_START_URLS_AS_SET = False
REDIS_START_URLS_KEY = '%(name)s:start_urls'
REDIS_ENCODING = 'utf-8'

SCHEDULER = 'scrapy_redis.scheduler.Scheduler'
SCHEDULER_SERIALIZER = 'scrapy_redis.picklecompat'
# SCHEDULER_SERIALIZER = 'json'
SCHEDULER_PERSIST = True
SCHEDULER_QUEUE_CLASS = 'scrapy_redis.queue.FifoQueue'
SCHEDULER_IDLE_BEFORE_CLOSE = 0
SCHEDULER_DEBUG = False

DUPEFILTER_DEBUG = False
DUPEFILTER_CLASS = 'amazon_demo.dupefilters.DummyDupeFilter'

# proxy settings
PROXY_POOL_ENABLED = False
PROXY_POOL_FILTER_ANONYMOUS = True
PROXY_POOL_FILTER_TYPES = 'https'
PROXY_POOL_FILTER_CODE = 'us'
PROXY_POOL_REFRESH_INTERVAL = 600
PROXY_POOL_CLOSE_SPIDER = False
PROXY_POOL_FORCE_REFRESH = True
PROXY_POOL_TRY_WITH_HOST = True
PROXY_POOL_PAGE_RETRY_TIMES = 3
PROXY_POOL_BAN_POLICY = 'amazon_demo.utils.AmazonBanDetectionPolicy'

LOG_STDOUT = False

RETRY_WITH_SPLASH = False
SPLASH_URL = 'http://35.193.17.116:8050'