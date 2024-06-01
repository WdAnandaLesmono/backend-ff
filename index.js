require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const admin = require('firebase-admin');
const serviceAccount = JSON.parse(process.env.FIREBASE_CONFIG);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const app = express();
app.use(bodyParser.json());

// Register
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  try {
    const userRecord = await admin.auth().createUser({
      email: email,
      password: password,
    });
    res.status(201).send({ message: 'User registered successfully', user: userRecord });
  } catch (error) {
    res.status(400).send({ error: error.message });
  }
});

// Login
app.post('/login', async (req, res) => {
  const { email } = req.body;

  try {
    const userRecord = await admin.auth().getUserByEmail(email);
    const customToken = await admin.auth().createCustomToken(userRecord.uid);
    
    res.status(200).send({ message: 'Login successful', token: customToken });
    
  } catch (error) {
    res.status(400).send({ error: error.message });
  }
});

// Autentikasi Token
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401);

  try {
    const decodedToken = await admin.auth().verifyIdToken(token);
    req.user = decodedToken;
    next();
  } catch (error) {
    console.log('Error verifying ID token:', error);
    return res.sendStatus(403);
  }
};

app.get('/protected', authenticateToken, (req, res) => {
  res.send({ message: 'This is a protected route', user: req.user });
});

app.get('/users', async (req, res) => {
  try {
    const listUsersResult = await admin.auth().listUsers(1000);
    listUsersResult.users.forEach((userRecord) => {
      console.log('user', userRecord.toJSON());
    });
    res.status(200).send(listUsersResult.users);
  } catch (error) {
    console.log('Error listing users:', error);
    res.status(500).send({ error: error.message });
  }
});

// PORT
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
