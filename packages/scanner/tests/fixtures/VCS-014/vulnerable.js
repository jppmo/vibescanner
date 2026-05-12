async function getUser(id) {
  return await db.query(`SELECT * FROM users WHERE id = ${id}`);
}

async function listTable(table) {
  return db.execute("SELECT * FROM " + table);
}

async function search(name) {
  return await db.raw(`SELECT * FROM products WHERE name = '${name}'`);
}
