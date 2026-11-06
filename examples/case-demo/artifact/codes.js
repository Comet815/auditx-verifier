// server/codes.js —— 兑换码生成（示例代码，故意留了缺陷）
function makeCode(len) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
  let out = ""
  for (let i = 0; i < len; i++) {
    // BUG: Math.random 不是密码学安全的
    out += chars.charAt(Math.floor(Math.random() * chars.length))
  }
  return out
}

module.exports = { makeCode }
