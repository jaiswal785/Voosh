// Import necessary modules
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Sequelize, DataTypes } = require('sequelize');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');
const aws = require('aws-sdk');
const multer = require('multer');
const multerS3 = require('multer-s3');

require('dotenv').config()

// Create an instance of Express
const app = express();

// Use middleware to parse JSON bodies
app.use(bodyParser.json());

const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Voosh API Documentation',
      version: '1.0.0',
      description: 'API documentation for Voosh application',
    },
  },
  apis: ['main.js'],
};

const specs = swaggerJsdoc(options);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs));

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
  },
  image_url: {
    type: DataTypes.STRING, // Store the URL of the user's image
    allowNull: true, // Allow null initially, as the user may not have uploaded an image yet
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

// Set up AWS S3
const s3 = new aws.S3({
  // Configure AWS credentials and region
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION,
});

// Set up Multer to handle file uploads
const upload = multer({
  storage: multerS3({
    s3: s3,
    bucket: process.env.AWS_S3_BUCKET_NAME,
    acl: 'public-read', // Set ACL to public-read so that uploaded images are publicly accessible
    metadata: function (req, file, cb) {
      cb(null, { fieldName: file.fieldname });
    },
    key: function (req, file, cb) {
      cb(null, Date.now().toString() + '-' + file.originalname);
    },
  }),
});

/**
 * @swagger
 * tags:
 *   name: Authentication
 *   description: User authentication endpoints
 */

/**
 * @swagger
 * /register:
 *   post:
 *     summary: Register a new user
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *               name:
 *                 type: string
 *     responses:
 *       '201':
 *         description: User registered successfully
 *       '400':
 *         description: Registration failed
 */
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

/**
 * @swagger
 * /login:
 *   post:
 *     summary: Log in
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 example: random@dummy.com
 *               password:
 *                 type: string
 *     responses:
 *       '200':
 *         description: Successful login
 *       '401':
 *         description: Authentication failed
 */
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

/**
 * @swagger
 * /logout:
 *   post:
 *     summary: Log out
 *     description: Client is expected to delete access token at their end
 *     responses:
 *       '200':
 *         description: Description of successful logout
 */
app.post('/logout', async (req, res) => {
    res.status(200).json({ description: "client is expected to delete access-token at their end" });
});

/**
 * @swagger
 * /profile:
 *   get:
 *     summary: Get user profile
 *     description: Returns logged-in user's profile details
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       '200':
 *         description: User profile retrieved successfully
 *       '401':
 *         description: Authentication failed
 */
app.get('/profile', authenticateUser, (req, res) => {
  // Return logged-in user's profile details
  res.status(200).json(req.user);
});

/**
 * @swagger
 * /profile:
 *   put:
 *     summary: Update user profile
 *     description: Updates logged-in user's profile details
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               name:
 *                 type: string
 *     responses:
 *       '200':
 *         description: User profile updated successfully
 *       '401':
 *         description: Authentication failed
 *       '400':
 *         description: Profile update failed
 */
app.put('/profile', authenticateUser, async (req, res) => {
  try {
    // Update user's profile details
    const updatedUser = await req.user.update(req.body);
    res.status(200).json(updatedUser);
  } catch (error) {
    res.status(400).json({ message: 'Profile update failed', error: error.message });
  }
});

/**
 * @swagger
 * /profile/visibility:
 *   put:
 *     summary: Set profile visibility
 *     description: Updates logged-in user's profile visibility
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               isPublic:
 *                 type: boolean
 *     responses:
 *       '200':
 *         description: Profile visibility updated successfully
 *       '401':
 *         description: Authentication failed
 *       '400':
 *         description: Failed to update profile visibility
 */
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

/**
 * @swagger
 * /admin/profiles:
 *   get:
 *     summary: Get all user profiles
 *     description: Retrieves all user profiles (both public and private) - Admin only
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       '200':
 *         description: User profiles retrieved successfully
 *       '401':
 *         description: Authentication failed
 *       '403':
 *         description: Admin authorization required
 *       '500':
 *         description: Failed to fetch user profiles
 */
app.get('/admin/profiles', authenticateUser, authorizeAdmin, async (req, res) => {
  try {
    // Find all user profiles
    const profiles = await User.findAll();
    res.status(200).json(profiles);
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch user profiles', error: error.message });
  }
});

/**
 * @swagger
 * /profiles:
 *   get:
 *     summary: Get public user profiles
 *     description: Retrieves all public user profiles
 *     responses:
 *       '200':
 *         description: Public user profiles retrieved successfully
 *       '500':
 *         description: Failed to fetch public user profiles
 */
app.get('/profiles', async (req, res) => {
  try {
    // Find all public user profiles
    const profiles = await User.findAll({ where: { is_public: true } });
    res.status(200).json(profiles);
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch public user profiles', error: error.message });
  }
});


/**
 * @swagger
 * /user/image:
 *   post:
 *     summary: Upload user image
 *     description: Uploads a user image to AWS S3 and updates the user's image URL in the database.
 *     tags: [User]
 *     security:
 *       - BearerAuth: []
 *     consumes:
 *       - multipart/form-data
 *     parameters:
 *       - in: formData
 *         name: image
 *         type: file
 *         description: The image file to upload
 *         required: true
 *     responses:
 *       '200':
 *         description: User image updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: A success message
 *                 imageUrl:
 *                   type: string
 *                   format: uri
 *                   description: The URL of the uploaded image
 *       '401':
 *         description: Authentication failed
 *       '500':
 *         description: Failed to update user image
 */
app.post('/user/image', authenticateUser, upload.single('image'), async (req, res) => {
  try {
    // Get user ID from request headers or authentication token
    const userId = req.user.id; // Assuming you have authentication middleware that attaches user object to request

    // Get uploaded image URL from AWS S3
    const imageUrl = req.file.location;

    // Update user's image URL in the database
    await User.update({ image_url: imageUrl }, { where: { id: userId } });

    res.status(200).json({ message: 'User image updated successfully', imageUrl: imageUrl });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Failed to update user image', error: error.message });
  }
});

// Start server
app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
