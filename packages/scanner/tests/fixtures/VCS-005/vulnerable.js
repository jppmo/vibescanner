const express = require('express')
const router = express.Router()
const db = require('./db')

// No middleware, no req.user check — vulnerable
router.get('/api/users', async (req, res) => {
  const users = await db.query('SELECT * FROM users')
  res.json(users)
})

// No middleware — vulnerable
router.delete('/api/users/:id', async (req, res) => {
  await db.query('DELETE FROM users WHERE id = $1', [req.params.id])
  res.sendStatus(204)
})

// Public path — should NOT be flagged
router.post('/login', async (req, res) => {
  const user = await db.findByEmail(req.body.email)
  res.json({ token: generateToken(user) })
})

module.exports = router
