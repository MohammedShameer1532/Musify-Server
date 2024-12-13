
const express = require('express');
const dotenv = require('dotenv');
dotenv.config();
const cors = require('cors');
const app = express();
const cookieParser = require('cookie-parser')
const session = require('express-session');
const MongoStore = require('connect-mongo');
const passport = require('passport');
const oAuth2Strategy = require('passport-google-oauth20').Strategy;
const PORT = process.env.PORT || 5000;
const ClientId = process.env.client_id;
const ClientSecret = process.env.client_secret;
const userDb = require('./Model/schema');
require('./db/database');



// Middleware
app.use(cors({
  origin: ["https://musify-client-eta.vercel.app"],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());
app.use(cookieParser())

//setup session
app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI, collectionName: "session" }),
  cookie: {
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24, // 1 day
    sameSite: 'None',
    secure: true,
    domain: '.vercel.app',
  },

}));



//setup passport
app.use(passport.initialize())
app.use(passport.session())

passport.use(
  new oAuth2Strategy({
    clientID: ClientId,
    clientSecret: ClientSecret,
    callbackURL: "https://musify-server-phi.vercel.app/auth/google/callback",
    scope: ["profile", "email"]
  }, async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await userDb.findOne({
        googleId: profile.id
      });
      if (!user) {
        user = new userDb({
          googleId: profile.id,
          displayName: profile.displayName,
          email: profile?.emails[0]?.value,
          image: profile?.photos[0]?.value
        });
        await user.save();
      }
      console.log("User found/created:", user);
      return done(null, user)
    } catch (error) {
      console.error("Error in OAuth callback:", error);
      return done(error, null)

    }
  })
)

passport.serializeUser((user, done) => {
  console.log("Serialized User ID:", user._id);
  done(null, user._id);
})
passport.deserializeUser(async (id, done) => {
  try {
    const user = await userDb.findById(id); // Retrieve user by ID
    console.log("Deserialized User:", user);
    done(null, user);
  } catch (error) {
    console.error("Error in deserializing user:", error);
    done(error, null);
  }
});


// initial google ouath login
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
app.get("/auth/google/callback", passport.authenticate("google", {
  successRedirect: "https://musify-client-eta.vercel.app/home",
  failureRedirect: "https://musify-client-eta.vercel.app"
}))



//Traditional Signup
app.post('/signup', async (req, res) => {
  console.log('Request Body:', req.body);
  const { name, email, password } = req.body;
  try {
    const existingUser = await userDb.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: "User already exists!" });
    }
    const newUser = new userDb({
      name,
      email,
      password,
    });
    await newUser.save();
    req.login(newUser, (err) => {
      console.log(newUser);
      if (err) return res.status(500).json({ message: "Signup failed" });
      return res.status(201).json({ message: "Signup successful", user: newUser });
    });
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});

//Traditional Login
app.post('/login', async (req, res) => {
  console.log('Request login:', req.body);
  console.log('Request Headers:', req.headers);
  const { email, password } = req.body;
  try {
    const user = await userDb.findOne({ email })
    if (!user || user.password !== password) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    req.login(user, (err) => {
      console.log("Session after login:", req.session);
      if (err) return res.status(500).json({ message: "Login failed" });
      return res.status(200).json({ message: "Login successful", user });
    });
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
})

app.get('/logout', (req, res, next) => {
  req.logout(function (err) {
    if (err) { return next(err) }
    res.redirect("https://musify-client-eta.vercel.app");
  })
})


app.get('/login/success', (req, res) => {
  if (req.isAuthenticated()) {
    res.status(200).json({
      success: true,
      message: "Login successful",
      user: req.user
    });
  } else {
    res.status(401).json({
      success: false,
      message: "Not authenticated"
    });
  }
});

app.use((req, res, next) => {
  console.log("Session Middleware:", req.session);
  next();
});

app.get('/', (req, res) => {
  res.send("Welcome to the server!");
});



const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ message: "Not authenticated" });
};

app.listen(PORT, (req, res) => {
  console.log(`running on port ${PORT}`);
})

module.exports = app;