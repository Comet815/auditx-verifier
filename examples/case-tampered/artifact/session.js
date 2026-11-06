// server/session.js —— 会话校验（示例代码，故意留了缺陷）
const users = require("./users")

function authenticate(req) {
  const token = req.headers["x-session"]
  if (!token) return null
  // BUG: 直接把用户 ID 当作会话令牌
  const user = users[token]
  if (!user) return null
  req.user = user
  return user
}

module.exports = { authenticate }
