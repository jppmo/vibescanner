async function getUser(id) {
  return await db.query("SELECT * FROM users WHERE id = ?", [id]);
}

async function search(name) {
  return await db.query("SELECT * FROM products WHERE name = $1", [name]);
}

async function getAll() {
  return await db.query("SELECT * FROM users");
}
