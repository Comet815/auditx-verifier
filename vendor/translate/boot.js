/*
 * translate.js 启动配置 · 落地页多语言
 * ---------------------------------------------------------------
 * 目标：一切翻译都来自 vendor/translate/dict.js 的本地词库，
 * **运行期间不对任何第三方发起请求**。这一点由 e2e 测试断言，
 * 不是口头承诺（见 README.md「验证」一节）。
 *
 * 做了什么：
 *  1. service 切到 client.edge —— 语种表改用脚本内置 JSON，
 *     否则初始化会去 api.translate.zvo.cn 拉 language.json。
 *  2. init / language 两个接口路径置空 —— 关掉版本检查与语种表请求。
 *  3. 本地语种固定 chinese_simplified。
 *
 * 为什么用 client.edge 而不是默认的 translate.service：
 *   默认通道会先对多个节点做连通性测速（connectTest.json），
 *   再拉 language.json / init.json，天然联网。client.edge 不做这些。
 *
 * 兜底说明：若某个文本节点没进词库，translate.js 会回落到 client.edge
 * 的在线接口（edge.microsoft.com）。所以「改文案必须同步加词条」，
 * 并跑一次测试。词库覆盖率由 e2e 断言保证。
 */
(function () {
  'use strict';

  if (typeof translate === 'undefined') {
    console.error('[auditx] translate.js 未加载，多语言不可用，页面保持中文');
    return;
  }

  var LOCAL = 'chinese_simplified';
  var LANGS = ['chinese_simplified', 'japanese', 'korean'];

  // —— 关闭外部请求 ——
  translate.service.use('client.edge');
  translate.request.api.init = '';
  translate.request.api.language = '';

  // —— 离线兜底闸 ——
  // 若某个文本节点没进词库，translate.js 会回落到 client.edge 的在线接口
  // （https://edge.microsoft.com/...）。这里把该绝对地址改成同源占位路径：
  // 未命中的请求只会在本机 404，文字保持原文，绝不会外发。
  // 这不是「正常路径」，出现 404 就说明词库漏了，请补词条。
  translate.service.edge.api.translate =
    '/__translate_offline_blocked__?from={from}&to={to}';

  translate.language.setLocal(LOCAL);

  // —— 语言切换器 ——
  function syncActive() {
    var current = LOCAL;
    try { current = translate.language.getCurrent() || LOCAL; } catch (e) {}
    var links = document.querySelectorAll('.lang a[data-lang]');
    for (var i = 0; i < links.length; i++) {
      var on = links[i].getAttribute('data-lang') === current;
      links[i].classList.toggle('on', on);
      links[i].setAttribute('aria-current', on ? 'true' : 'false');
    }
  }

  function bind() {
    var links = document.querySelectorAll('.lang a[data-lang]');
    for (var i = 0; i < links.length; i++) {
      links[i].addEventListener('click', function (ev) {
        ev.preventDefault();
        var code = this.getAttribute('data-lang');
        if (LANGS.indexOf(code) === -1) return;
        Promise.resolve(translate.changeLanguage(code)).then(syncActive, syncActive);
      });
    }
    syncActive();
  }

  translate.listener.start();

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bind);
  } else {
    bind();
  }

  // 上次访问若停在某个译语，翻译要跟着恢复（默认停在中文则不执行翻译）
  var saved = null;
  try { saved = translate.language.getCurrent(); } catch (e) {}
  if (saved && saved !== LOCAL && LANGS.indexOf(saved) !== -1) {
    translate.changeLanguage(saved);
    setTimeout(syncActive, 400);
  }
})();
