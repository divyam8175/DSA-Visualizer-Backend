const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const User = require('../models/User');

// Local Strategy
passport.use(new LocalStrategy({
  usernameField: 'email',
  passwordField: 'password'
}, async (email, password, done) => {
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return done(null, false, { message: 'Incorrect email or password' });
    }

    // Check if user has a password (not a social login user)
    if (!user.password) {
      return done(null, false, { message: 'Please use social login for this account' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return done(null, false, { message: 'Incorrect email or password' });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    return done(null, user);
  } catch (error) {
    return done(error);
  }
}));

// Google Strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: '/api/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
  try {
    // Check if user exists with Google ID
    let user = await User.findOne({ googleId: profile.id });

    if (!user) {
      // Check if user exists with the same email
      user = await User.findOne({ email: profile.emails[0].value });
      if (user) {
        // Link Google account to existing user
        user.googleId = profile.id;
        user.profilePicture = profile.photos[0].value;
        await user.save();
      } else {
        // Create new user
        user = new User({
          googleId: profile.id,
          email: profile.emails[0].value,
          name: profile.displayName,
          profilePicture: profile.photos[0].value
        });
        await user.save();
      }
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    return done(null, user);
  } catch (error) {
    return done(error);
  }
}));

// GitHub Strategy
passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_CLIENT_SECRET,
  callbackURL: '/api/auth/github/callback'
}, async (accessToken, refreshToken, profile, done) => {
  try {
    // Check if user exists with GitHub ID
    let user = await User.findOne({ githubId: profile.id });

    if (!user) {
      // Check if user exists with the same email
      const email = profile.emails && profile.emails[0] ? profile.emails[0].value : null;
      if (email) {
        user = await User.findOne({ email });
        if (user) {
          // Link GitHub account to existing user
          user.githubId = profile.id;
          user.profilePicture = profile.photos[0].value;
          await user.save();
        }
      }

      if (!user) {
        // Create new user
        user = new User({
          githubId: profile.id,
          email: email || `${profile.username}@github.com`,
          name: profile.displayName || profile.username,
          profilePicture: profile.photos[0].value
        });
        await user.save();
      }
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    return done(null, user);
  } catch (error) {
    return done(error);
  }
}));

// Serialize user
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Deserialize user
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    if (!user) {
      return done(null, false);
    }
    done(null, user);
  } catch (error) {
    done(error);
  }
}); 