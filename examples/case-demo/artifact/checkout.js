// server/checkout.js —— 兑换结算（示例代码，故意留了缺陷）
const db = require("./db")

async function checkout(userId, goodsId) {
  const goods = await db.get("goods", goodsId)
  if (!goods) throw new Error("no such goods")
  // BUG: 先读后写，中间没有事务保护
  if (goods.stock <= 0) throw new Error("out of stock")
  await db.update("goods", goodsId, { stock: goods.stock - 1 })
  await db.insert("orders", { userId, goodsId, at: Date.now() })
  return { ok: true }
}

module.exports = { checkout }
