require('dotenv').config(); // Load environment variables first

const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const multer = require('multer');
const UserModel = require('./models/user');

const app = express();

// Configuration
const JWT_SECRET = process.env.JWT_SECRET;
const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 12;

// Validate required environment variables
if (!JWT_SECRET) {
  console.error('FATAL ERROR: JWT_SECRET is not defined in environment variables.');
  process.exit(1);
}

// Configure multer for file uploads with validation
const upload = multer({
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
    files: 2 // Max 2 files (avatar + cover)
  },
  fileFilter: (req, file, cb) => {
    // Only allow image files
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'), false);
    }
  }
});

// Middleware setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser());

// Security headers middleware
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// Authentication middleware
const verifyToken = async (req, res, next) => {
  try {
    const token = req.cookies.token;
    
    if (!token) {
      return res.status(401).redirect('/login?error=unauthorized');
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await UserModel.findById(decoded.userid);
    
    if (!user) {
      res.clearCookie('token');
      return res.status(401).redirect('/login?error=user_not_found');
    }
    
    req.user = user;
    next();
  } catch (error) {
    console.error('Token verification error:', error.message);
    res.clearCookie('token');
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).redirect('/login?error=token_expired');
    }
    
    return res.status(401).redirect('/login?error=invalid_token');
  }
};

// Helper function to generate JWT token
const generateToken = (user) => {
  return jwt.sign(
    { 
      email: user.email, 
      userid: user._id 
    }, 
    JWT_SECRET, 
    { 
      expiresIn: '7d' // Token expires in 7 days
    }
  );
};

// Public routes
app.get('/', (req, res) => {
  res.render('index', { 
    title: 'FundMatch - Connect Startups with Investors' 
  });
});

app.get('/login', (req, res) => {
  const error = req.query.error;
  let errorMessage = null;
  
  switch (error) {
    case 'unauthorized':
      errorMessage = 'Please log in to access this page.';
      break;
    case 'token_expired':
      errorMessage = 'Your session has expired. Please log in again.';
      break;
    case 'invalid_token':
      errorMessage = 'Invalid session. Please log in again.';
      break;
    case 'user_not_found':
      errorMessage = 'User account not found.';
      break;
  }
  
  res.render('login', { 
    title: 'Login - FundMatch',
    error: errorMessage 
  });
});

app.get('/signup', (req, res) => {
  res.render('signup', { 
    title: 'Sign Up - FundMatch',
    error: null 
  });
});

// Authentication routes
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Input validation
    if (!email || !password) {
      return res.status(400).render('login', {
        title: 'Login - FundMatch',
        error: 'Email and password are required.'
      });
    }

    // Find user
    const user = await UserModel.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(400).render('login', {
        title: 'Login - FundMatch',
        error: 'Invalid email or password.'
      });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(400).render('login', {
        title: 'Login - FundMatch',
        error: 'Invalid email or password.'
      });
    }

    // Generate token and set cookie
    const token = generateToken(user);
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      sameSite: 'strict'
    });

    res.redirect('/profile');
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).render('login', {
      title: 'Login - FundMatch',
      error: 'An error occurred during login. Please try again.'
    });
  }
});

app.post('/signup', async (req, res) => {
  try {
    const { fullname, email, company, password } = req.body;
    
    // Input validation
    if (!fullname || !email || !password) {
      return res.status(400).render('signup', {
        title: 'Sign Up - FundMatch',
        error: 'Full name, email, and password are required.'
      });
    }

    if (password.length < 8) {
      return res.status(400).render('signup', {
        title: 'Sign Up - FundMatch',
        error: 'Password must be at least 8 characters long.'
      });
    }

    // Check if user already exists
    const existingUser = await UserModel.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).render('signup', {
        title: 'Sign Up - FundMatch',
        error: 'An account with this email already exists.'
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    // Create new user
    const newUser = await UserModel.create({
      fullname: fullname.trim(),
      email: email.toLowerCase(),
      company: company?.trim() || '',
      password: hashedPassword
    });

    // Generate token and set cookie
    const token = generateToken(newUser);
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      sameSite: 'strict'
    });

    res.redirect('/profile');
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).render('signup', {
      title: 'Sign Up - FundMatch',
      error: 'An error occurred during registration. Please try again.'
    });
  }
});

// Protected routes
app.get('/logout', verifyToken, (req, res) => {
  res.clearCookie('token');
  res.redirect('/login');
});

app.get('/profile', verifyToken, (req, res) => {
  res.render('profile', { 
    title: 'Profile - FundMatch',
    user: req.user 
  });
});

app.get('/profile/edit', verifyToken, (req, res) => {
  res.render('editProfile', { 
    title: 'Edit Profile - FundMatch',
    user: req.user 
  });
});

app.post('/profile/update', verifyToken, async (req, res) => {
  try {
    const { fullname, company, bio } = req.body;
    
    // Input validation
    if (!fullname || fullname.trim().length === 0) {
      return res.status(400).render('editProfile', {
        title: 'Edit Profile - FundMatch',
        user: req.user,
        error: 'Full name is required.'
      });
    }

    // Update user profile
    const updatedUser = await UserModel.findByIdAndUpdate(
      req.user._id,
      {
        fullname: fullname.trim(),
        company: company?.trim() || '',
        bio: bio?.trim() || ''
      },
      { new: true, runValidators: true }
    );

    if (!updatedUser) {
      throw new Error('User not found');
    }

    res.redirect('/profile?success=profile_updated');
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).render('editProfile', {
      title: 'Edit Profile - FundMatch',
      user: req.user,
      error: 'Error updating profile. Please try again.'
    });
  }
});

app.post('/profile/upload', verifyToken, upload.fields([
  { name: 'avatar', maxCount: 1 }, 
  { name: 'cover', maxCount: 1 }
]), async (req, res) => {
  try {
    const updateData = {};
    
    // Process avatar upload
    if (req.files?.avatar?.[0]) {
      updateData.avatar = req.files.avatar[0].buffer;
    }
    
    // Process cover upload
    if (req.files?.cover?.[0]) {
      updateData.cover = req.files.cover[0].buffer;
    }

    // Only update if there are files to upload
    if (Object.keys(updateData).length > 0) {
      await UserModel.findByIdAndUpdate(req.user._id, updateData);
    }

    res.redirect('/profile?success=images_uploaded');
  } catch (error) {
    console.error('File upload error:', error);
    
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).render('profile', {
        title: 'Profile - FundMatch',
        user: req.user,
        error: 'File size too large. Maximum size is 5MB.'
      });
    }
    
    if (error.message === 'Only image files are allowed') {
      return res.status(400).render('profile', {
        title: 'Profile - FundMatch',
        user: req.user,
        error: 'Only image files are allowed.'
      });
    }

    res.status(500).render('profile', {
      title: 'Profile - FundMatch',
      user: req.user,
      error: 'Upload error. Please try again.'
    });
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).render('error', {
    title: 'Error - FundMatch',
    message: 'An unexpected error occurred.'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).render('404', {
    title: 'Page Not Found - FundMatch'
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received. Shutting down gracefully...');
  process.exit(0);
});

// Start server
app.listen(PORT, () => {
  console.log(` Server running on http://localhost:${PORT}`);
  console.log(` Environment: ${process.env.NODE_ENV || 'development'}`);
});