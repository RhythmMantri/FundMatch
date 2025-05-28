require('dotenv').config(); // Load env vars at top

const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const multer = require('multer');
const upload = multer();
const UserModel = require('./models/user');

const app = express();

// Middleware
app.set('view engine', 'ejs');
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser());

// Load secret key from env
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret';

// Middleware to verify JWT token
const verifyToken = async (req, res, next) => {
  try {
    const token = req.cookies.token;
    if (!token) return res.redirect('/login');

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await UserModel.findById(decoded.userid);
    if (!user) return res.redirect('/login');

    req.user = user;
    next();
  } catch (error) {
    console.error('Token verification error:', error);
    res.redirect('/login');
  }
};

// Routes
app.get('/', (req, res) => res.render('index'));
app.get('/login', (req, res) => res.render('login'));
app.get('/signup', (req, res) => res.render('signup'));

app.get('/logout', (req, res) => {
  res.clearCookie("token");
  res.redirect('/login');
});

app.get('/profile', verifyToken, (req, res) => {
  res.render('profile', { user: req.user });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await UserModel.findOne({ email });
  if (!user) return res.status(400).send('Invalid email');

  bcrypt.compare(password, user.password, (err, result) => {
    if (result) {
      const token = jwt.sign({ email, userid: user._id }, JWT_SECRET);
      res.cookie('token', token);
      res.redirect('/profile');
    } else {
      res.redirect('/login');
    }
  });
});

app.post('/signup', async (req, res) => {
  const { fullname, email, company, password } = req.body;
  const existingUser = await UserModel.findOne({ email });
  if (existingUser) return res.status(400).send('User already registered');

  bcrypt.genSalt(10, (err, salt) => {
    bcrypt.hash(password, salt, async (err, hash) => {
      const newUser = await UserModel.create({ fullname, email, company, password: hash });
      const token = jwt.sign({ email, userid: newUser._id }, JWT_SECRET);
      res.cookie('token', token);
      res.redirect("login");
    });
  });
});

// Profile edit routes
app.get('/profile/edit', verifyToken, (req, res) => {
  res.render('editProfile', { user: req.user });
});

app.post('/profile/update', verifyToken, async (req, res) => {
  try {
    const { fullname, company, bio } = req.body;
    await UserModel.findByIdAndUpdate(req.user._id, { fullname, company, bio });
    res.redirect('/profile');
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).send('Error updating profile');
  }
});

app.post('/profile/upload', verifyToken, upload.fields([{ name: 'avatar' }, { name: 'cover' }]), async (req, res) => {
  try {
    const avatar = req.files?.avatar?.[0]?.buffer;
    const cover = req.files?.cover?.[0]?.buffer;

    await UserModel.findByIdAndUpdate(req.user._id, {
      ...(avatar && { avatar }),
      ...(cover && { cover }),
    });

    res.redirect('/profile');
  } catch (err) {
    console.error('File upload error:', err);
    res.status(500).send('Upload error');
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(` Server running on http://localhost:${PORT}`);
});
