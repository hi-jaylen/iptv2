# 标准库
import os
import re
import json
import logging
import requests
from datetime import datetime
from urllib.parse import urlparse
from itertools import islice
from collections import OrderedDict
from configparser import ConfigParser, NoOptionError
# 第三方库
import zhconv
import typing as t
# 自定义模块

# 设置日志级别，基于环境变量DEBUG
DEBUG = os.environ.get('DEBUG') is not None
IPTV_CONFIG = os.environ.get('IPTV_CONFIG') or 'config.ini'
IPTV_CHANNEL = os.environ.get('IPTV_CHANNEL') or 'channel.txt'
IPTV_DIST = os.environ.get('IPTV_DIST') or 'dist'

def parse_bool_env(var_name, default=False):
    return os.environ.get(var_name, str(default)).lower() in ('true', '1', 'yes')
EXPORT_RAW = parse_bool_env('EXPORT_RAW', DEBUG)
EXPORT_JSON = parse_bool_env('EXPORT_JSON', DEBUG)



# 默认配置
DEF_LINE_LIMIT = 10
DEF_REQUEST_TIMEOUT = 100 # 处理source的超时时间
DEF_USER_AGENT = 'okhttp/4.12.0-iptv'
DEF_INFO_LINE = 'https://liuliuliu.tv/api/channels/1997/stream'
DEF_EPG = 'https://raw.githubusercontent.com/JinnLynn/iptv/dist/epg.xml'
DEF_IPV4_FILENAME_SUFFIX = '-ipv4'
DEF_WHITELIST_PRIORITY =10 # 白名单优先级

# 配置日志格式
logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format='[%(asctime)s][%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()])

# 自定义有序集合类，用于维护元素顺序
T = t.TypeVar("T")
class OrderedSet(t.MutableSet[T]):
    def __init__(self, iterable: t.Optional[t.Iterable[T]] = None):
        self._d = OrderedDict.fromkeys(iterable) if iterable else OrderedDict()

    def add(self, x: T) -> None:
        self._d[x] = None

    def discard(self, x: T) -> None:
        self._d.pop(x, None)

    def __contains__(self, x: object) -> bool:
        return x in self._d

    def __len__(self) -> int:
        return len(self._d)

    def __iter__(self) -> t.Iterator[T]:
        return iter(self._d)


# 自定义JSON编码器以处理集合
class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, set):
            return list(o)
        return super().default(o)

# 使用自定义设置导出JSON
def json_dump(obj, fp=None, **kwargs):
    kwargs.setdefault('cls', JSONEncoder)
    kwargs.setdefault('indent', 2)
    kwargs.setdefault('ensure_ascii', False)
    return json.dump(obj, fp, **kwargs) if fp else json.dumps(obj, **kwargs)

# 将字符串转换为布尔值
def conv_bool(v):
    if isinstance(v, bool):
        return v
    return ConfigParser.BOOLEAN_STATES[v.lower()]

# 将多行字符串转换为列表
def conv_list(v):
    v = v.strip().splitlines()
    return [s.strip() for s in v if s.strip()]

# 将字符串转换为字典
def conv_dict(v):
    maps = {}
    for m in conv_list(v):
        s = re.split(r'\ +', m)

        if len(s) != 2:
            logging.error(f'字典配置错误: {m} => {s}')
            continue
        maps[s[0].strip()] = s[1].strip()
    return maps

# 清理字符串中的行内注释
def clean_inline_comment(v):
    def _remove_inline_comment(l):
        try:
            l = re.split(r' +#', l)[0]
        except Exception as e:
            logging.warning(f'行内注释清理出错: {l} {e}')
        return l
    return '\n'.join([_remove_inline_comment(s) for s in v.strip().splitlines()])

# 检查URL是否使用IPv6
def is_ipv6(url):
    p = urlparse(url)
    return re.match(r'\[[0-9a-fA-F:]+\]', p.netloc) is not None

# IPTV主类
class IPTV:
    def __init__(self, *args, **kwargs):
        self._cate_logos = None
        self._channel_map = None
        self._blacklist = None
        self._whitelist = None
        self.raw_config = None
        self.raw_channels = {}
        self.channel_cates = OrderedDict()
        self.channels = {}

    # 获取配置值并进行可选转换
    def get_config(self, key, *convs, default=None):
        if not self.raw_config:
            self.raw_config = ConfigParser()

            # 读取配置文件，确保存在
            self.raw_config = ConfigParser()
            config_files = [c.strip() for c in IPTV_CONFIG.split(',')]
            for config_file in config_files:
                if os.path.isfile(config_file):
                    self.raw_config.read(config_file, encoding='utf-8')
                else:
                    logging.error(f'配置文件不存在: {config_file}')

        try:
            value = self.raw_config.get('config', key)
            value = clean_inline_comment(value)
            if value.strip() == '':  # 检查是否为空或仅包含空格
                return default
            if convs:
                for conv in convs:
                    value = conv(value)
        except NoOptionError:
            return default
        except Exception as e:
            logging.error(f'获取配置出错: {key} {e}')
            return default
        return value

    # 获取分发文件的路径
    def _get_path(self, dist, filename):
        if not os.path.isdir(dist):
            os.makedirs(dist, exist_ok=True)
        abspath = os.path.join(dist, filename)
        if not os.path.isdir(os.path.dirname(abspath)):
            os.makedirs(os.path.dirname(abspath), exist_ok=True)
        return abspath

    # 获取文件的分发路径
    def get_dist(self, filename, ipv4_suffix=False):
        parts = filename.rsplit('.', 1)
        if ipv4_suffix:
            parts[0] = f'{parts[0]}{DEF_IPV4_FILENAME_SUFFIX}'
        return self._get_path(IPTV_DIST, '.'.join(parts))

    # 从配置加载分类图标
    @property
    def cate_logos(self):
        if self._cate_logos is None:
            self._cate_logos = self.get_config('logo_cate', conv_dict, default={})
        return self._cate_logos

    # 从配置加载频道映射
    @property
    def channel_map(self):
        if self._channel_map is None:
            original_map = self.get_config('channel_map', conv_dict, default={})
            # 交换键和值，并处理多个值
            self._channel_map = {}
            for k, v in original_map.items():
                # 将值根据中文逗号分割
                for name in v.split('，'):
                    # 处理键值对，用中文冒号分割
                    self._channel_map[name.strip()] = k.strip()  # 去除空格并添加到映射中
        return self._channel_map

    # 黑名单和白名单处理
    def read_list_from_file(self, file_name):
        current_dir = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(current_dir, file_name)

        if os.path.isfile(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                return [
                    line.split(',', 1)[-1].strip().split('#', 1)[0].strip() if ',' in line else
                    line.strip().split('#', 1)[0].strip()
                    for line in f if line.strip() and not line.startswith('#')
                ]
        return []

    # 从配置加载黑名单
    @property
    def blacklist(self):
        if self._blacklist is None:
            self._blacklist = self.get_config('blacklist', conv_list, default=[])
            self._blacklist.extend(self.read_list_from_file('blacklist.txt'))
            self._blacklist = list(set(self._blacklist))  # 去重
        return self._blacklist

    # 从配置加载白名单
    @property
    def whitelist(self):
        if self._whitelist is None:
            self._whitelist = self.get_config('whitelist', conv_list, default=[])
            self._whitelist.extend(self.read_list_from_file('whitelist.txt'))
            self._whitelist = list(set(self._whitelist))  # 去重
        return self._whitelist

    # 从频道文件加载频道
    def load_channels(self):
        for f in IPTV_CHANNEL.split(','):
            current = ''
            with open(f.strip(), encoding='utf-8') as fp:
                for line in fp:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if line.startswith('CATE:'):
                        current = line[5:].strip()
                        self.channel_cates.setdefault(current, OrderedSet())
                    else:
                        if not current:
                            logging.warning(f'忽略没有指定分类的频道: {line}')
                            continue

                        if line.startswith('-'):
                            line = line[1:].strip()
                            if line in self.channel_cates[current]:
                                self.channel_cates[current].remove(line)
                        else:
                            self.channel_cates[current].add(line)

        for v in self.channel_cates.values():
            for c in v:
                self.channels.setdefault(c, [])

    # 从URL获取数据
    def fetch(self, url):
        headers = {'User-Agent': DEF_USER_AGENT}
        res = requests.get(url, timeout=DEF_REQUEST_TIMEOUT, headers=headers)
        res.raise_for_status()
        return res

    # 从配置获取源
    def fetch_sources(self):
        # 从配置中获取源 URL 列表，默认值为空列表
        sources = self.get_config('source', conv_list, default=[])
        success_count = 0  # 成功获取的源计数
        failed_sources = []  # 存储获取失败的源

        for url in sources:
            try:
                # 检查 URL 是否为本地文件路径
                if os.path.isfile(url):
                    with open(url, 'r', encoding='utf-8') as file:
                        res_content = file.readlines()  # 读取本地文件内容
                    res = [line.encode() for line in res_content]  # 模拟响应为字节形式
                    #logging.info(f'读取本地文件成功: {url}')
                else:
                    res = self.fetch(url)  # 获取在线内容
            except Exception as e:
                # 记录获取失败的源及错误信息
                logging.warning(f'获取失败❌: {url} {e}')
                failed_sources.append(url)  # 添加到失败列表
                continue

            # 检查前10行是否包含 M3U 格式的标识
            try:
                is_m3u = any('#EXTINF' in l.decode(errors='ignore') for l in islice(res, 10))
            except Exception as e:
                # 记录检查 M3U 格式时的错误
                logging.warning(f'检查 M3U 格式时出错: {url} {e}')
                failed_sources.append(url)
                continue

            logging.info(f'获取成功✔️: {"M3U" if is_m3u else "TXT"} {url}')
            success_count += 1  # 成功计数加一

            cur_cate = None  # 当前频道分类

            # 对于在线内容，确保使用 iter_lines() 处理响应
            for line in (res if isinstance(res, list) else res.iter_lines()):
                try:
                    line = line.decode(errors='ignore').strip()  # 解码行并去除空白
                except Exception as e:
                    # 记录解码行时的错误
                    logging.warning(f'解码行时出错: {e}')
                    continue

                if not line:
                    continue  # 跳过空行

                if is_m3u:
                    # 处理 M3U 格式
                    if line.startswith("#EXTINF"):
                        match = re.search(r'group-title="(.*?)",(.*)', line)
                        if match:
                            cur_cate = match.group(1).strip()  # 获取当前分类
                            chl_name = match.group(2).strip()  # 获取频道名称
                    elif not line.startswith("#"):
                        # 处理频道 URL
                        channel_url = line.strip()
                        self.add_channel_uri(chl_name, channel_url)  # 添加频道 URI
                else:
                    # 处理 TXT 格式
                    if "#genre#" in line:
                        cur_cate = line.split(",")[0].strip()  # 获取当前分类
                    elif cur_cate:
                        match = re.match(r"^(.*?),(.*?)$", line)
                        if match:
                            chl_name = match.group(1).strip()  # 获取频道名称
                            channel_url = match.group(2).strip()  # 获取频道 URL
                            self.add_channel_uri(chl_name, channel_url)  # 添加频道 URI

        # 记录读取源的结果
        logging.info(f'源读取完毕: 成功: {success_count} 失败: {len(failed_sources)}')
        if failed_sources:
            logging.warning(f'获取失败的源❌: {failed_sources}')  # 记录失败的源
        self.stat_fetched_channels()  # 更新获取的频道统计信息

    # 检查URL中的端口是否必要
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

    # 清理频道名称
    def clean_channel_name(self, name):
        def re_subs(s, *reps):
            for rep in reps:
                r = ''
                c = 0
                if len(rep) == 1:
                    p = rep[0]
                elif len(rep) == 2:
                    p, r = rep
                else:
                    p, r, c = rep
                s = re.sub(p, r, s, c)
            return s
        def any_startswith(s, *args):
            return any([re.search(fr'^{r}', s, re.IGNORECASE) for r in args])

        def any_in(s, *args):
            return any(a in s for a in args)

        # 繁体中文转换为简体
        jap = re.compile(r'[\u3040-\u309F\u30A0-\u30FF\uAC00-\uD7A3]')  # 匹配日文和韩文字符
        if not jap.search(name):
            name = zhconv.convert(name, 'zh-cn', {'「': '「', '」': '」'})

        if name.startswith('CCTV'): #channel.txt可匹配名称CCTV1至CCTV17。
            name = re_subs(name,
                                (r'-[(HD)0]*', ),                           # CCTV-0 CCTV-HD
                                (r'(CCTV[1-9][0-9]?[\+K]?).*', r'\1')
            )
        elif name.startswith('CETV'): #channel.txt可匹配名称CETV1至CETV4
            name = re_subs(name,
                                (r'[ -][(HD)0]*', ),
                                (r'(CETV[1-4]).*', r'\1'),
            )
        elif any_startswith(name, 'NewTV', 'CHC', 'iHOT'):
            for p in ['NewTV', 'CHC', 'iHOT']:
                name = re.sub(fr'^{p}', p, name, 1, re.IGNORECASE)
                if not name.startswith(p):
                    continue
                name = re_subs(name,
                                    (re.compile(f'{p} +'), p, 1),
                                    (r'(.*) +.*', r'\1')
                )
        elif re.match(r'^TVB[^s]', name, re.IGNORECASE):
            name = name.replace(' ', '')
        return name

    # 为调试目的添加频道
    def add_channel_for_debug(self, name, url, org_name, org_url):
        if name not in self.raw_channels:
            self.raw_channels.setdefault(name, OrderedDict(source_names=set(), source_urls=set(), lines=[]))

        self.raw_channels[name]['source_names'].add(org_name)
        self.raw_channels[name]['source_urls'].add(org_url)

        self.raw_channels[name]['lines_dict'] = {}
        if url in self.raw_channels[name]['lines_dict']:
            self.raw_channels[name]['lines_dict'][url]['count'] += 1
        else:
            self.raw_channels[name]['lines_dict'][url] = {'uri': url, 'count': 1, 'ipv6': is_ipv6(url)}

    # 尝试使用频道映射
    def try_map_channel_name(self, name):
        if name in self.channel_map.keys():
            o_name = name
            name = self.channel_map[name]
            logging.debug(f'映射频道名: {o_name} => {name}')
        return name

    # 添加频道URI
    def add_channel_uri(self, name, uri):
        uri = re.sub(r'\$.*', '', uri)

        name = self.try_map_channel_name(name)

        # 处理频道名称
        org_name = name
        name = self.clean_channel_name(name)
        if org_name != name:
            logging.debug(f'规范频道名: {org_name} => {name}')

        name = self.try_map_channel_name(name)

        changed = False
        p = urlparse(uri)
        try:
            if self.is_port_necessary(p.scheme, p.netloc):
                changed = True
                p = p._replace(netloc=p.netloc.rsplit(':', 1)[0])
        except Exception as e:
            logging.debug(f'频道线路地址出错: {name} {uri} {e}')
            return

        url = p.geturl() if changed else uri

        self.add_channel_for_debug(name, url, org_name, uri)

        if name not in self.channels:
            return

        if self.is_on_blacklist(url):
            logging.debug(f'黑名单忽略: {name} {uri}')
            return

        priority = DEF_WHITELIST_PRIORITY if self.is_on_whitelist(url) else 0
        for u in self.channels[name]:
            if u['uri'] == url:
                u['count'] = u['count'] + 1
                u['priority'] = u['count'] + priority
                return
        self.channels[name].append({'uri': url, 'priority': priority + 1, 'count': 1, 'ipv6': is_ipv6(url)})

    # 按优先级排序频道
    def sort_channels(self):
        for k in self.channels:
            self.channels[k].sort(key=lambda i: i['priority'], reverse=True)

    # 待获取频道总数
    def stat_fetched_channels(self):
        logging.info(f'需获取频道数: {len(self.channels)}')

    # 检查URL是否在黑名单中
    def is_on_blacklist(self, url):
        return any(b in url for b in self.blacklist) # 字符串包含匹配
        #return any(re.search(re.escape(b), url) for b in self.blacklist) # 正则表达式匹配

    # 检查URL是否在白名单中
    def is_on_whitelist(self, url):
        return any(b in url for b in self.whitelist) # 字符串包含匹配
        #return any(re.search(re.escape(b), url) for b in self.whitelist) # 正则表达式匹配

    # 枚举频道URI，带可选限制
    def enum_channel_uri(self, name, limit=None, only_ipv4=False):
        if name not in self.channels:
            return []
        if limit is None:
            limit = self.get_config('limit', int, default=DEF_LINE_LIMIT)
        index = 0
        for chl in self.channels[name]:
            if only_ipv4 and chl['ipv6']:
                continue
            index = index + 1
            if isinstance(limit, int) and limit > 0 and index > limit:
                return
            yield index, chl

    # 以指定格式导出信息
    def export_info(self, fmt='m3u', fp=None):
        if self.get_config('disable_export_info', conv_bool, default=False):
            return
        day = datetime.now().strftime('%Y-%m-%d')
        url = self.get_config('info_line', default=DEF_INFO_LINE)
        output = []

        if fmt == 'm3u':
            logo_url_prefix = self.get_config('logo_url_prefix', lambda s: s.rstrip('/'))
            output.append(f'#EXTINF:-1 group-title="{day}更新",{day}更新')
            output.append(f'{url}')
        else:
            output.append(f'{day}更新,#genre#')
            output.append(f'{day}更新,{url}')

        output = '\n'.join(output)
        if fp:
            fp.write(output)
        return output

    # 获取导出文件名，带可选IPv4后缀
    def get_export_filename(self, filename, only_ipv4=False):
        parts = filename.rsplit('.', 1)
        if only_ipv4:
            parts[0] = f'{parts[0]}-ipv4'
        return '.'.join(parts)

    # 导出频道为M3U格式
    def export_m3u(self, only_ipv4=False):
        dst = self.get_dist('live.m3u', ipv4_suffix=only_ipv4)
        logo_url_prefix = self.get_config('logo_url_prefix', lambda s: s.rstrip('/'))

        with open(dst, 'w', encoding='utf-8') as fp:  # 指定编码为utf-8
            fp.write('#EXTM3U x-tvg-url="{}"\n'.format(self.get_config('epg', default=DEF_EPG)))
            for cate, chls in self.channel_cates.items():
                for chl_name in chls:
                    for index, uri in self.enum_channel_uri(chl_name, only_ipv4=only_ipv4):
                        logo = f'{chl_name}.png'  # 默认 logo
                        if chl_name in self.cate_logos:
                            logo = self.cate_logos[chl_name]  # 从 cate_logos 中获取 logo

                        # 根据是否在 cate_logos 中来设置 tvg-logo
                        tvg_logo = logo if chl_name in self.cate_logos else f'{logo_url_prefix}/{logo}'

                        fp.write(
                            f'#EXTINF:-1 tvg-id="{index}" tvg-name="{chl_name}" tvg-logo="{tvg_logo}" group-title="{cate}",{chl_name}\n')
                        fp.write('{}\n'.format(uri['uri']))

            self.export_info(fmt='m3u', fp=fp)

        if not only_ipv4:
            logging.info(f'导出M3U: {dst}')
        else:
            logging.info(f'导出M3U（IPV4）: {dst}')

    # 导出频道为TXT格式
    def export_txt(self, only_ipv4=False):
        dst = self.get_dist('live.txt', ipv4_suffix=only_ipv4)
        unique_channels = set()  # 使用集合来存储唯一频道名称

        with open(dst, 'w', encoding='utf-8') as fp:  # 指定编码为utf-8
            for cate, chls in self.channel_cates.items():
                fp.write(f'{cate},#genre#\n')
                for chl_name in chls:
                    for index, uri in self.enum_channel_uri(chl_name, only_ipv4=only_ipv4):
                        fp.write('{},{}\n'.format(chl_name, uri['uri']))
                        unique_channels.add(chl_name)  # 将频道名称添加到集合中
                fp.write('\n')

            self.export_info(fmt='txt', fp=fp)

        # 计算唯一频道数量并记录，除非只导出IPv4版本
        if not only_ipv4:
            unique_channel_count = len(unique_channels)  # 计算唯一频道数量
            logging.info(f'导出TXT: {dst}')

            line_num = sum(len(v) for v in self.channels.values())
            logging.info(f'已获取频道数: {unique_channel_count} 线路总数: {line_num}')

        else:
            logging.info(f'导出TXT（IPV4）: {dst}')  # 导出ipv4版本

    # 导出频道为JSON格式
    def export_json(self, only_ipv4=False):
        dst = self.get_dist('raw/channel.json', ipv4_suffix=only_ipv4)
        data = OrderedDict()

        for cate, chls in self.channel_cates.items():
            data.setdefault(cate, OrderedDict())
            for chl_name in chls:
                data[cate].setdefault(chl_name, [])
                for index, uri in self.enum_channel_uri(chl_name, only_ipv4=only_ipv4):
                    data[cate][chl_name].append(uri)

        with open(dst, 'w', encoding='utf-8') as fp:  # 确保使用UTF-8编码
            json_dump(data, fp, sort_keys=False)  # 确保保持插入顺序

        logging.info(f'导出JSON: {dst}')

    # 导出原始频道数据
    def export_raw(self):
        dst = self.get_dist('raw/source.json')
        for k in self.raw_channels:
            self.raw_channels[k]['lines'].sort(key=lambda i: i['count'], reverse=True)
        with open(dst, 'w') as fp:
            json_dump(self.raw_channels, fp)
        logging.info(f'导出RAW: {dst}')

    # 导出所有数据
    def export(self):
        self.sort_channels()

        self.export_m3u()
        self.export_txt()

        if EXPORT_JSON:
            self.export_json()

        if self.get_config('export_ipv4_version', conv_bool, default=False):
            self.export_m3u(only_ipv4=True)
            self.export_txt(only_ipv4=True)
            if EXPORT_JSON:
                self.export_json(only_ipv4=True)

        if EXPORT_RAW:
            self.export_raw()


    # 主运行函数
    def run(self):
        self.load_channels()
        self.fetch_sources()
        self.export()

# 脚本的入口点
if __name__ == '__main__':
    iptv = IPTV()
    iptv.run()
