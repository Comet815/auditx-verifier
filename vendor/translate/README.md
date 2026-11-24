# vendor/translate —— 落地页多语言（自托管）

给 `index.html`（演示站落地页）加日/韩切换用的最小依赖。**不是**给 `examples/*/verify.html` 用的：
那三个页面的卖点是「纯手写 SHA-256 / Ed25519、无第三方库、不联网」，一行外部 JS 都不该进去。

## 装了什么

| 文件 | 来源 | 说明 |
|---|---|---|
| `translate.min.js` | [xnx3/translate](https://github.com/xnx3/translate) `v4.0.0`（2026-02-10） | 上游 `translate.js/translate.min.js`，149,870 字节，未改一行 |
| `dict.js` | 本仓库 | 离线词库，日/韩各约 26 条，覆盖落地页全部文本节点 |
| `boot.js` | 本仓库 | 启动配置 + 语言切换器 + 离线兜底闸 |

`translate.min.js` 的完整性由 `index.html` 上的 SRI 锁定：

```
sha384-B5hwYQH9C5z0qPkxL7uG0WEuQQRmnBzZuJMopnFeIJcg5Txz45XKfq0fBA+vM+o2
```

上游一旦改动，浏览器会直接拒绝执行——改这个文件必须同时改 `integrity`。

## 为什么是「自托管 + 锁版本」

上游推荐的用法是引 `https://res.zvo.cn/translate/translate.js`（CDN，且不带版本号）。
对一个做安全审查的产品来说，落地页引一条随时可变、无法固定哈希的第三方脚本，是自己给自己开口子。
所以这里改成把产物放进仓库、用 SRI 锁定。代价是升级要手动做一次（只有 150 KB）。

## 为什么要关掉一堆东西

translate.js 默认会对外发若干请求，逐条关掉：

| 默认行为 | 关法 | 原因 |
|---|---|---|
| 多节点测速 `connectTest.json` | 改用 `client.edge` 服务通道 | 离线场景没有「选最快节点」这回事 |
| 语种表 `language.json` | 同上，改用脚本内置的语种 JSON | 只要用到的那几个语种，不需要远端全量列表 |
| 版本检查 `init.json` | `translate.request.api.init = ''` | 纯静态页，不需要它提示升级 |
| 机翻回落 `edge.microsoft.com` | 把接口地址改成本机占位路径 | **最关键的一条**，见下 |

### 离线兜底闸

词库是哈希匹配的：页面某段文字没进 `dict.js`，translate.js 就会**默默回落到微软的在线翻译接口**。
这在离线/隐私场景里是致命的——它不会报错，只会把中文悄悄发出去，拿回一段机翻。

`boot.js` 里把 `translate.service.edge.api.translate` 改成了同源占位路径：

```js
translate.service.edge.api.translate =
  '/__translate_offline_blocked__?from={from}&to={to}';
```

于是漏词条的后果变成：本机一个 404、那段文字保持原文。**不会外发。**
DevTools 里看到 `/__translate_offline_blocked__` 就是词库漏了，按原文去 `dict.js` 补一行。

## 改文案之后必须做什么

`dict.js` 的 key 是**文本节点的原文，逐字一致，包括行尾空格**。
比如「源码与命令行版本见 」结尾那个空格是链接前的分隔符，少一个就对不上。

所以流程是：

1. 改 `index.html`
2. 按新文案补/改 `dict.js` 的日、韩两行
3. 跑下面的验证，`misses` 必须为空数组

## 验证（2026-11-24 实测）

在 Chromium 里加载页面，依次切 日 → 韩 → 日 → 中，记录两件事：

**一、窗口期网络请求**——除同源 4 条外，**零外部请求**：

```
GET  /index.html                        200
GET  /vendor/translate/translate.min.js 304
GET  /vendor/translate/dict.js          200
GET  /vendor/translate/boot.js          304
```

（整轮切换期间无任何指向 `zvo.cn`、`microsoft.com` 的请求。）

**二、词库命中率**——遍历 `translate.nodeQueue`，对每个节点查 `translate.storage`：

```js
translate.storage.get('hash_japanese_' + hash)   // 全部非空
translate.storage.get('hash_korean_'   + hash)   // 全部非空
```

实测：日文 26/26 命中，韩文 26/26 命中，`misses = []`。
中文 → 日 → 韩 → 中 来回切换，文本与 `<title>` 均正确还原。

**三、回归**——`examples/*/verify.html` 未受影响：页面内 `typeof translate === 'undefined'`，
验签结果照旧（case-demo 12 条事件、7/7 校验通过）。

## 已知限制

- 页面文案一改就要手动补词条，没有自动化门禁。若以后文案开始频繁变动，应该把上面第二步做成脚本。
- 只做了日、韩。要加第三个语种，在 `boot.js` 的 `LANGS`、`index.html` 的切换器、`dict.js` 三处各加一份。
- 英文仍走手写的 `index-en.html`，不经 translate.js——产品页的英文宁可手写，机翻压不住语气。
- 语言选择存在 localStorage，回访会记住上次选的语种。
