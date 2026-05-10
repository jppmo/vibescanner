const express = require('express')
const router = express.Router()
const { authenticate } = require('./middleware/auth')
const db = require('./db')

// Protected by middleware
router.get('/api/users', authenticate, async (req, res) => {
  const users = await db.query('SELECT * FROM users')
  res.json(users)
})

// Protected by req.user check
router.delete('/api/users/:id', async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Unauthorized' })
  await db.query('DELETE FROM users WHERE id = $1', [req.params.id])
  res.sendStatus(204)
})

// Public — no auth needed
router.post('/login', async (req, res) => {
  const user = await db.findByEmail(req.body.email)
  res.json({ token: generateToken(user) })
})

module.exports = router
