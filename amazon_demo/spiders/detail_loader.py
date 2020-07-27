# -*- coding: utf-8 -*-

import os
import re
import traceback

import scrapy
from scrapy_redis.spiders import RedisSpider
from scrapy_redis.utils import bytes_to_str
from scrapy_splash import SplashRequest

from amazon_page_parser import MARKETPLACES
from amazon_page_parser.parsers import DetailParser


class DetailLoaderSpider(RedisSpider):
    name = 'detail_loader'
    allowed_domains = [m['domain'] for m in MARKETPLACES.values()]
    custom_settings = {
        'ITEM_PIPELINES': {
            'amazon_demo.pipelines.AmazonDetailPipeline': 300
        }
    }

    def parse(self, response):
        marketplace = response.request.meta['marketplace']
        asin = response.request.meta['asin']
        if response.status >= 500:
            retry_with_splash = self.settings.getbool('RETRY_WITH_SPLASH', False)
            if retry_with_splash:
                message = '[SplashRequest] URL: {}, headers: {}, meta: {}'.format(
                    response.request.url, str(response.request.headers), str(response.request.meta))
                self.logger.info(message)

                return SplashRequest(
                    response.request.url, args={'wait': 1},
                    headers=response.request.headers, meta=response.request.meta, dont_filter=True)

            message = '[RequestFailed] URL: {}, headers: {}, meta: {}'.format(
                response.request.url, str(response.request.headers), str(response.request.meta))
            self.logger.info(message)

            return

        parser = DetailParser(response.text)
        item = {
            'marketplace': marketplace,
            'asin': asin
        }
        try:
            item['detail'] = parser.parse()
            item['detail']['asin'] = asin
        except Exception as e:
            self.logger.exception(e)

            item['error'] = {
                'stacktrace': traceback.format_exc(e),
                'page_source': response.text
            }

        return item

    def extract_asin_from_url(self, url):
        matched = re.match(r'.*www\.amazon\.com\/dp\/([0-9A-Z]{10}).*', url)
        return '' if matched is None or len(matched.groups()) <= 0 else matched.groups()[0]

    def make_request_from_data(self, data):
        marketplace_asin = bytes_to_str(data, self.redis_encoding)
        marketplace, asin = marketplace_asin.split(':')

        return self.get_product_request(marketplace, asin)

    def get_product_request(self, marketplace, asin):
        marketplace = marketplace.lower()
        if marketplace not in MARKETPLACES:
            return None

        domain = MARKETPLACES[marketplace]['domain']
        url = 'https://{}/dp/{}'.format(domain, asin)
        referer = 'https://{}/s/ref=nb_sb_noss_2?url=search-alias=aps&field-keywords={}'.format(
            domain, asin)

        return scrapy.Request(url, headers={'Referer': referer}, meta={'marketplace': marketplace, 'asin': asin})
