const express = require('express');
const dotenv = require('dotenv');
dotenv.config();
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();
const cookieParser = require('cookie-parser');
const passport = require('passport');
const oAuth2Strategy = require('passport-google-oauth20').Strategy;
const PORT = process.env.PORT || 5000;
const ClientId = process.env.client_id;
const ClientSecret = process.env.client_secret;
const userDb = require('./Model/schema');
require('./db/database');

// Middleware
app.use(cors({
  origin: ["http://localhost:5173"],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true,
}));
app.use(express.json());
app.use(cookieParser());

// Create JWT Token
const generateToken = (user) => {
  const payload = {
    googleId: user._id,
    email: user.email,
    displayName: user.displayName,
    image: user.image,
    name: user.name
  };
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1d' }); // Token valid for 1 day
};

// Setup passport for Google OAuth
passport.use(
  new oAuth2Strategy({
    clientID: ClientId,
    clientSecret: ClientSecret,
    callbackURL: "https://musify-server-phi.vercel.app/auth/google/callback",
    scope: ["profile", "email"],
  }, async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await userDb.findOne({ googleId: profile.id });
      if (!user) {
        user = new userDb({
          googleId: profile.id,
          displayName: profile.displayName,
          email: profile?.emails[0]?.value,
          image: profile?.photos[0]?.value,
        });
        await user.save();
      }
      return done(null, user);
    } catch (error) {
      return done(error, null);
    }
  })
);

passport.serializeUser((user, done) => {
  done(null, user._id);
});
passport.deserializeUser(async (id, done) => {
  try {
    const user = await userDb.findById(id);
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

// Initial Google OAuth login
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
app.get("/auth/google/callback", passport.authenticate("google", { session: false }), (req, res) => {
  if (!req.user) {
    return res.status(400).json({ message: "Authentication failed" });
  }

  // Generate JWT Token
  const token = generateToken(req.user);
  console.log('Generated token:', token);

  // Send the token and user details back to the client
  res.cookie('token', token, {
    httpOnly: true,   // Ensures the cookie can't be accessed via JavaScript (protection against XSS)
    secure: true, // Ensures the cookie is sent over HTTPS in production
    maxAge: 24 * 60 * 60 * 1000,  // Token validity (1 day)
    sameSite: 'Strict',  // Helps prevent CSRF attacks
  });
  res.redirect(`http://localhost:5173/home`);
});



// Traditional Signup
app.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const existingUser = await userDb.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: "User already exists!" });
    }

    const hashedPassword = await bcrypt.hash(password, 10); // Hash the password before saving it
    const newUser = new userDb({ name, email, password: hashedPassword });
    await newUser.save();

    // Generate JWT Token
    const token = generateToken(newUser);
    // Send the token and user details back to the client
    res.cookie('token', token, {
      httpOnly: true,   // Ensures the cookie can't be accessed via JavaScript (protection against XSS)
      secure: true, // Ensures the cookie is sent over HTTPS in production
      maxAge: 24 * 60 * 60 * 1000,  // Token validity (1 day)
      sameSite: 'Strict',  // Helps prevent CSRF attacks
    });
    res.status(201).json({ message: "Signup successful", token, user: newUser });
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});

// Traditional Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await userDb.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // Compare password with hashed password in the database
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // Generate JWT Token
    const token = generateToken(user);
    // Send the token and user details back to the client
    res.cookie('token', token, {
      httpOnly: true,   // Ensures the cookie can't be accessed via JavaScript (protection against XSS)
      secure: true, // Ensures the cookie is sent over HTTPS in production
      maxAge: 24 * 60 * 60 * 1000,  // Token validity (1 day)
      sameSite: 'Strict',  // Helps prevent CSRF attacks
    });
    res.status(200).json({ message: "Login successful", token, user });
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});

// Middleware to verify JWT token
const authenticateJWT = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ message: "Access denied, no token provided" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid token" });
    }
    req.user = user; // Attach user info to request object
    next();
  });
};

// Example protected route
app.get('/login/success', authenticateJWT, (req, res) => {
  console.log("athu", authenticateJWT);
  console.log("req", req.user);
  if (req.user) {
    res.status(200).json({ message: "User successfully logged in", user: req.user });
  } else {
    res.status(401).json({ message: "Not Authorized" });
  }
});

// Logout - Remove the JWT token from the client
app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.status(200).json({ message: "Logged out successfully" });
});

// Home route
app.get('/', (req, res) => {
  res.send("Welcome to the server!");
});

app.listen(PORT, () => {
  console.log(`Running on port ${PORT}`);
});

module.exports = app;
