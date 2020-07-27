# -*- coding: utf-8 -*-

import traceback

import scrapy
from scrapy_redis.spiders import RedisSpider
from scrapy_redis.utils import bytes_to_str
from scrapy_splash import SplashRequest

from amazon_page_parser import MARKETPLACES
from amazon_page_parser.parsers import OfferListingParser


class OfferListingLoaderSpider(RedisSpider):
    name = 'offer_listing_loader'
    allowed_domains = [m['domain'] for m in MARKETPLACES.values()]
    custom_settings = {
        'ITEM_PIPELINES': {
            'amazon_demo.pipelines.AmazonOfferListingPipeline': 300
        },
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

        item = {
            'marketplace': marketplace,
            'asin': asin,
        }
        parser = OfferListingParser(response.text)
        try:
            item['offer_listing'] = parser.parse()
        except Exception as e:
            self.logger.exception(e)

            item['error'] = {
                'stacktrace': traceback.format_exc(e),
                'page_source': response.text
            }

        return item

    def make_request_from_data(self, data):
        marketplace_asin = bytes_to_str(data, self.redis_encoding)
        marketplace, asin = marketplace_asin.split(':')
        return self.get_offer_listing_request(marketplace, asin)

    def get_offer_listing_request(self, marketplace, asin):
        marketplace = marketplace.lower()
        if marketplace not in MARKETPLACES:
            return None

        domain = MARKETPLACES[marketplace]['domain']
        url = 'https://{}/gp/offer-listing/{}'.format(domain, asin)
        referer = "https://{}/dp/{}".format(domain, asin)

        return scrapy.Request(
            url, headers={'Referer': referer}, meta={'marketplace': marketplace, 'asin': asin})
