const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const db = require('./db');
const cors = require('cors');

const app = express();
const port = 3000;
const secretKey = 'your-secret-key';

app.use(cors());
app.use(bodyParser.json());

// Public route
app.get('/api/data', (req, res) => {
  res.json({ message: 'This is public data' });
});

// Register route
app.post('/api/register', async (req, res) => {
  // Extracting all fields from your sign-up form
  const { 
    username, 
    email, 
    password, 
    name, 
    surname, 
    secondSurname 
  } = req.body;

  // Basic "fail-safe" validation
  if (!username || !email || !password || !name || !surname) {
    return res.status(400).json({ message: 'Missing required fields' });
  }

  try {
    // 1. Check for existing user/email in Neon
    const userCheck = await db.query(
      'SELECT id FROM users WHERE username = $1 OR email = $2', 
      [username, email]
    );
    
    if (userCheck.rows.length > 0) {
      return res.status(409).json({ message: 'Username or Email already exists' });
    }

    // 2. Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // 3. Insert into the database
    // Note: second_surname is optional, so we handle nulls
    const queryText = `
      INSERT INTO users (username, email, password_hash, first_name, surname, second_surname) 
      VALUES ($1, $2, $3, $4, $5, $6) 
      RETURNING id, username
    `;
    const values = [username, email, hashedPassword, name, surname, secondSurname || null];

    const newUser = await db.query(queryText, values);

    res.status(201).json({ 
      message: 'User created successfully', 
      userId: newUser.rows[0].id 
    });

  } catch (err) {
    console.error('Database Error:', err);
    res.status(500).json({ message: 'Server error during registration' });
  }
});

// Login route
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password required' });
  }

  try {
    // 1. Find user (Allows logging in with either Username or Email)
    const result = await db.query(
      'SELECT * FROM users WHERE username = $1 OR email = $1', 
      [username]
    );
    const user = result.rows[0];

    // 2. Security Check: Generic message for privacy
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // 3. Compare provided password with our Neon 'password_hash' column
    const validPassword = await bcrypt.compare(password, user.password_hash);
    
    if (!validPassword) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // 4. Generate token with useful payload data
    const payload = { 
      id: user.id, 
      username: user.username,
      name: user.first_name // Optional: useful for displaying "Hello, Name" in UI
    };

    jwt.sign(payload, secretKey, { expiresIn: '1h' }, (err, token) => {
      if (err) {
        console.error('JWT Error:', err);
        return res.status(500).json({ message: 'Error generating session' });
      }
      res.json({ 
        message: 'Login successful',
        token 
      });
    });

  } catch (err) {
    console.error('Database Error:', err);
    res.status(500).json({ message: 'Server error during login' });
  }
});

// Protected route - Accesses data only with a valid token
app.get('/api/protected', verifyToken, (req, res) => {
  // Use the secretKey to verify the token extracted by the middleware
  jwt.verify(req.token, secretKey, (err, authData) => {
    if (err) {
      // If the token is expired or invalid, deny access
      res.status(403).json({ message: 'Session expired or invalid token' });
    } else {
      // Access granted: authData now contains the id, username, and name 
      // from your Neon DB user record
      res.json({
        message: 'This is protected data from Neon DB',
        user: {
          id: authData.id,
          username: authData.username,
          name: authData.name
        },
        timestamp: new Date().toISOString()
      });
    }
  });
});

// Middleware to verify the Authorization header
function verifyToken(req, res, next) {
  const bearerHeader = req.headers['authorization'];
  
  if (typeof bearerHeader !== 'undefined') {
    // Format is usually: "Bearer <token>"
    const bearer = bearerHeader.split(' ');
    const bearerToken = bearer[1];
    
    if (!bearerToken) {
      return res.status(403).json({ message: 'Token missing from header' });
    }
    
    req.token = bearerToken;
    next();
  } else {
    // Forbidden if header is missing
    res.status(403).json({ message: 'Authorization header is required' });
  }
}

app.listen(port, () => {
  console.log(`Server started on http://localhost:${port}`);
});