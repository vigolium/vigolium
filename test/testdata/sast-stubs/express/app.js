const express = require('express');
const app = express();
const router = express.Router();

// Basic CRUD routes
router.get('/users', (req, res) => {
  const q = req.query.q;
  const page = req.query.page;
  res.json({ users: [], q, page });
});

router.post('/users', (req, res) => {
  const name = req.body.name;
  const email = req.body.email;
  res.json({ name, email });
});

router.get('/users/:id', (req, res) => {
  const id = req.params.id;
  res.json({ id });
});

router.put('/users/:id', (req, res) => {
  const id = req.params.id;
  const name = req.body.name;
  res.json({ id, name });
});

router.delete('/users/:id', (req, res) => {
  const id = req.params.id;
  res.json({ deleted: id });
});

// Multiple methods
router.all('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Route group via middleware
app.use('/api/v1', router);

// Direct app routes
app.get('/status', (req, res) => {
  res.json({ status: 'running' });
});

app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  res.json({ token: 'abc' });
});

app.listen(3000);
