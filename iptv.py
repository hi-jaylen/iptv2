import os
from configparser import ConfigParser, NoOptionError
from collections import OrderedDict
import re
from urllib.parse import urlparse
import logging
import itertools
import typing as t
import json
from datetime import datetime

from pprint import pprint

import requests
import zhconv

DEF_LINE_LIMIT = 10
DEF_REQUEST_TIMEOUT = 10

DEBUG = os.environ.get('DEBUG', None) is not None

logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format='[%(asctime)s][%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()])

# REF: https://github.com/bustawin/ordered-set-37
T = t.TypeVar("T")
class OrderedSet(t.MutableSet[T]):
    __slots__ = ('_d',)

    def __init__(self, iterable: t.Optional[t.Iterable[T]] = None):
        self._d = dict.fromkeys(iterable) if iterable else {}

    def add(self, x: T) -> None:
        self._d[x] = None

    def clear(self) -> None:
        self._d.clear()

    def discard(self, x: T) -> None:
        self._d.pop(x, None)

    def __getitem__(self, index) -> T:
        try:
            return next(itertools.islice(self._d, index, index + 1))
        except StopIteration:
            raise IndexError(f"index {index} out of range")

    def __contains__(self, x: object) -> bool:
        return self._d.__contains__(x)

    def __len__(self) -> int:
        return self._d.__len__()

    def __iter__(self) -> t.Iterator[T]:
        return self._d.__iter__()

    def __str__(self):
        return f"{{{', '.join(str(i) for i in self)}}}"

    def __repr__(self):
        return f"<OrderedSet {self}>"


def conv_bool(v):
    return v.lower() in ['1', 'true', 'yes', 'on']

def conv_list(v):
    v = v.strip().split('\n')
    return [s.strip() for s in v if s.strip()]

def is_ipv6(url):
    p = urlparse(url)
    return re.match(r'\[[0-9a-fA-F:]+\]', p.netloc) is not None


class IPTV:
    def __init__(self, *args, **kwargs):
        self._cate_logos = None

        self.raw_config = None
        self.raw_channels = {}
        self.channel_cates = OrderedDict()
        self.channels = {}

    def get_config(self, key, *convs, default=None):
        if not self.raw_config:
            self.raw_config = ConfigParser()
            self.raw_config.read('config.ini')

        try:
            value = self.raw_config.get('config', key)
            if convs:
                for conv in convs:
                    value = conv(value)
                return value
            return default
        except NoOptionError:
            return default

    @property
    def cate_logos(self):
        if self._cate_logos is not None:
            return self._cate_logos
        self._cate_logos = {}
        for m in self.get_config('logo_cate', conv_list, default=[]):
            s = m.split(' ')
            self._cate_logos[s[0].strip()] = s[1].strip()
        return self._cate_logos

    def load_channels(self):
        current = ''
        with open('channel.txt') as fp:
            for line in fp.readlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if line.startswith('CATE:'):
                    current = line[5:].strip()
                    self.channel_cates.setdefault(current, OrderedSet())
                else:
                    if current:
                        self.channel_cates[current].add(line)
                        self.channels.setdefault(line, [])

    def fetch_sources(self):
        sources = self.get_config('source', conv_list, default=[])
        success_count = 0
        failed_sources = []
        for url in sources:
            try:
                headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36'}
                res = requests.get(url, timeout=DEF_REQUEST_TIMEOUT, headers=headers)
                res.raise_for_status()
                lines = res.content.decode().split('\n')
            except Exception as e:
                logging.warning(f'获取失败: {url} {e}')
                failed_sources.append(url)
                continue
            is_m3u = any('#EXTINF' in line for line in lines[:15])
            logging.info(f'获取成功: {"M3U" if is_m3u else "TXT"} {url}')
            success_count = success_count + 1

            cur_cate = None

            if is_m3u:
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith("#EXTINF"):
                        match = re.search(r'group-title="(.*?)",(.*)', line)
                        if match:
                            cur_cate = match.group(1).strip()
                            chl_name = match.group(2).strip()
                    elif not line.startswith("#"):
                        channel_url = line.strip()
                        self.add_channel_uri(chl_name, channel_url)
            else:
                for line in lines:
                    line = line.strip()
                    if "#genre#" in line:
                        cur_cate = line.split(",")[0].strip()
                    elif cur_cate:
                        match = re.match(r"^(.*?),(.*?)$", line)
                        if match:
                            chl_name = match.group(1).strip()
                            channel_url = match.group(2).strip()
                            self.add_channel_uri(chl_name, channel_url)
                        # FIX: 地址中会出现#分割的多个地址
                        # elif line:
        logging.info(f'源读取完毕: 成功: {success_count} 失败: {len(failed_sources)}')
        if failed_sources:
            logging.warning(f'获取失败的源: {failed_sources}')
        self.stat_fetched_channels()

    def is_port_necessary(self, scheme, netloc):
        if netloc[-1] == ']':
            return False

        out = netloc.rsplit(":", 1)
        if len(out) == 1:
            return False
        else:
            try:
                port = int(out[1])
                if scheme == 'http' and port == 80:
                    return True
                if scheme == 'https' and port == 443:
                    return True
            except ValueError:
                return False
        return False

    def clean_channel_name(self, name):
        # 繁 => 简
        jap = re.compile(r'[\u3040-\u309F\u30A0-\u30FF\uAC00-\uD7A3]')  # \uAC00-\uD7A3为匹配韩文的，其余为日文
        if not jap.search(name):
            name = zhconv.convert(name, 'zh-cn', {'「': '「', '」': '」'})

        if name.startswith('CCTV'):
            name = name.replace('-', '', 1)
            match = re.match(r'CCTV[0-9]+ ', name)
            if match:
                name = match[0].strip()
            name = name.split(' ')[0]
            match = re.match(r'CCTV[0-9\+K]+', name)
            if match:
                name = match[0].strip()

        for p in ['NewTV', 'CHC']:
            if name.startswith(p):
                name = name.replace(f'{p} ', p)
                name = name.split(' ')[0]

        return name

    def add_channel_for_debug(self, name, uri):
        if name not in self.raw_channels:
            self.raw_channels.setdefault(name, [])

        for u in self.raw_channels[name]:
            if u['uri'] == uri:
                u['count'] += u['count'] + 1
                return
        self.raw_channels[name].append({'uri': uri, 'count': 1, 'ipv6': is_ipv6(uri)})


    def add_channel_uri(self, name, uri):
        uri = re.sub(r'\$.*$', '', uri)

        if DEBUG:
            self.add_channel_for_debug(name, uri)

        # logging.debug(name)

        org_name = name
        name = self.clean_channel_name(name)
        if org_name != name:
            logging.debug(f'规范频道名: {org_name} => {name}')

        if name not in self.channels:
            return

        # TODO: clean more
        changed = False

        p = urlparse(uri)
        if self.is_port_necessary(p.scheme, p.netloc):
            changed = True
            p = p._replace(netloc=p.netloc.rsplit(':', 1)[0])

        url = p.geturl() if changed else uri

        for u in self.channels[name]:
            if u['uri'] == url:
                u['count'] += u['count'] + 1
                return
        self.channels[name].append({'uri': url, 'count': 1, 'ipv6': is_ipv6(url)})

        # if changed:
        #     logging.debug(f'URL cleaned: {uri} => \n                                              {p.geturl()}')

    def sort_channels(self):
        for k in self.channels:
            self.channels[k].sort(key=lambda i: i['count'], reverse=True)

    def stat_fetched_channels(self):
        line_num = sum([len(c) for c in self.channels])
        logging.info(f'获取的所需: 频道: {len(self.channels)} 线路: {line_num}')
        # TODO: 输出没有获取到任何线路的频道


    def enum_channel_uri(self, name, limit=None):
        if name not in self.channels:
            return []
        if limit is None:
            limit = self.get_config('limit', int, default=DEF_LINE_LIMIT)
        for index, chl in enumerate(self.channels[name]):
            if isinstance(limit, int) and limit > 0 and index >= limit:
                return
            yield index + 1, chl

    def export_m3u(self, dist):
        dst = os.path.join(dist, 'live.m3u')
        epgs = self.get_config('epg', conv_list, lambda d: ','.join(f'"{e}"' for e in d), default=[])
        logo_url_prefix = self.get_config('logo_url_prefix', lambda s: s.rstrip('/'))

        with open(dst, 'w') as fp:
            epg_urls = f' x-tvg-url={epgs}' if epgs else ''
            fp.write(f'#EXTM3U{epg_urls}\n')

            for cate, chls in self.channel_cates.items():
                for chl_name in chls:
                    for index, uri in self.enum_channel_uri(chl_name):
                        logo = self.cate_logos[cate] if cate in self.cate_logos else f'{chl_name}.png'
                        fp.write(f'#EXTINF:-1 tvg-id="{index}" tvg-name="{chl_name}" tvg-logo="{logo_url_prefix}/{logo}" group-title="{cate}",{chl_name}\n')
                        fp.write('{}${}『线路{}』\n'.format(uri['uri'], 'IPv6' if uri['ipv6'] else 'IPv4', index))
            # fp.write(f'#EXTINF:-1 tvg-id="1" tvg-name="{chl_name}" tvg-logo="{logo}" group-title="更新说明",{chl_nam}\n')
            # fp.write('{}${}『线路{}』\n'.format(uri['uri'], 'IPv6' if uri['ipv6'] else 'IPv4', index))
        logging.info(f'导出M3U: {dst}')

    def export_txt(self, dist):
        dst = os.path.join(dist, 'live.txt')
        with open(dst, 'w') as fp:
            for cate, chls in self.channel_cates.items():
                fp.write(f'{cate},#genre#\n')
                for chl_name in chls:
                    for index, uri in self.enum_channel_uri(chl_name):
                        fp.write('{},{}${}『线路{}』\n'.format(chl_name, uri['uri'], 'IPv6' if uri['ipv6'] else 'IPv4', index))
                fp.write('\n\n')
        logging.info(f'导出TXT: {dst}')

    def export(self):
        dist = 'dist'
        os.makedirs(dist, exist_ok=True)
        self.sort_channels()
        self.export_m3u(dist)
        self.export_txt(dist)

        if DEBUG:
            for k in self.raw_channels:
                self.raw_channels[k].sort(key=lambda i: i['count'], reverse=True)
            os.makedirs('tmp', exist_ok=True)
            with open('tmp/channels.json', 'w') as fp:
                json.dump(self.raw_channels, fp, indent=4)

    def run(self):
        self.load_channels()
        self.fetch_sources()
        self.export()


if __name__ == '__main__':
    iptv = IPTV()
    iptv.run()
