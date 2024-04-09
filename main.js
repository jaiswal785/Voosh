// Import necessary modules
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Sequelize, DataTypes } = require('sequelize');

// Create an instance of Express
const app = express();

// Use middleware to parse JSON bodies
app.use(bodyParser.json());

// Set up Sequelize to connect to PostgreSQL database
const sequelize = new Sequelize('voosh_db', 'postgres', 'postgres', {
  host: 'localhost',
  dialect: 'postgres',
});

// Define User model
const User = sequelize.define('user', {
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  name: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  // Add additional fields like bio, phone, photo URL, etc.
  // Add a field for profile visibility (public or private)
  is_public: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: true, // Default to public
  },
  is_admin: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: false,
  }
}, 
{
  timestamps: true,
  createdAt: "created_at",
  updatedAt: 'updated_at'
});

// Define middleware for authentication
const authenticateUser = async (req, res, next) => {
  try {
    // Extract token from request headers
    const token = req.headers.authorization.split(' ')[1];
    // Verify token
    const decoded = jwt.verify(token, 'secret');
    // Find user by ID from token
    const user = await User.findByPk(decoded.userId);
    // Attach user object to request
    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Authentication failed' });
  }
};

// Define middleware for admin authorization
const authorizeAdmin = (req, res, next) => {
  if (!req.user.is_admin) {
    return res.status(403).json({ message: 'Admin authorization required' });
  }
  next();
};

// Define routes
app.post('/register', async (req, res) => {
  try {
    // Hash password
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    // Create user
    const user = await User.create({
      email: req.body.email,
      password: hashedPassword,
      name: req.body.name,
      is_admin: req.body.isAdmin ?? false,
      is_public: req.body.isPublic ?? true
    });
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(400).json({ message: 'Registration failed', error: error.message });
  }
});

app.post('/login', async (req, res) => {
  try {
    // Find user by email
    const user = await User.findOne({ where: { email: req.body.email } });
    if (!user) {
      throw new Error('User not found');
    }
    // Compare passwords
    const passwordMatch = await bcrypt.compare(req.body.password, user.password);
    if (!passwordMatch) {
      throw new Error('Invalid password');
    }
    // Generate JWT token
    const token = jwt.sign({ userId: user.id }, 'secret', { expiresIn: '1h' });
    res.status(200).json({ token });
  } catch (error) {
    res.status(401).json({ message: 'Authentication failed', error: error.message });
  }
});

app.post('/logout', async (req, res) => {
    res.status(200).json({ description: "client is expected to delete access-token at their end" });
});

// Profile details endpoint (accessible only to authenticated users)
app.get('/profile', authenticateUser, (req, res) => {
  // Return logged-in user's profile details
  res.status(200).json(req.user);
});

// Profile update endpoint (accessible only to authenticated users)
app.put('/profile', authenticateUser, async (req, res) => {
  try {
    // Update user's profile details
    const updatedUser = await req.user.update(req.body);
    res.status(200).json(updatedUser);
  } catch (error) {
    res.status(400).json({ message: 'Profile update failed', error: error.message });
  }
});

// Set profile visibility endpoint (accessible only to authenticated users)
app.put('/profile/visibility', authenticateUser, async (req, res) => {
  try {
    // Update user's profile visibility
    console.log(req.body);
    const updatedUser = await req.user.update({ is_public: req.body.isPublic });
    res.status(200).json(updatedUser);
  } catch (error) {
    res.status(400).json({ message: 'Failed to update profile visibility', error: error.message });
  }
});

// Admin endpoint to get all user profiles (both public and private)
app.get('/admin/profiles', authenticateUser, authorizeAdmin, async (req, res) => {
  try {
    // Find all user profiles
    const profiles = await User.findAll();
    res.status(200).json(profiles);
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch user profiles', error: error.message });
  }
});

// Public profile endpoint (accessible to all users)
app.get('/profiles', async (req, res) => {
  try {
    // Find all public user profiles
    const profiles = await User.findAll({ where: { is_public: true } });
    res.status(200).json(profiles);
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch public user profiles', error: error.message });
  }
});


// Start server
app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
