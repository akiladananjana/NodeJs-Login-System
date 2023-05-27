const express = require("express");
const passport = require("passport");
const session = require("express-session");

// to display error messages
const flash = require("express-flash");

// to hash passwords
const bcrypt = require("bcrypt");

// store env data
const dotenv = require("dotenv");

dotenv.config({ path: "./env.config" });

// save user data locally
const users = [];

// import passport configs
const initializePassport = require("./passport-config");

const getUserByEmail = (email) => {
  return users.find((user) => {
    return user.email == email;
  });
};

const getUserById = (id) => {
  return users.find((user) => {
    return user.id == id;
  });
};

// init imported passport configs
initializePassport(passport, getUserByEmail, getUserById);

const app = express();
app.set("view-engine", "ejs");

// Set Middlewares

// read form data and attch to req object
app.use(express.urlencoded({ extended: false }));

// init flash for display errors
app.use(flash());

// init sessions for app
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);

// init passport to use on all routes
app.use(passport.initialize());

// allow passport to use sessions
app.use(passport.session());

const checkAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/login");
};

const checkNotAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return res.redirect("/");
  }
  next();
};

app.get("/", checkAuthenticated, (req, res) => {
  res.render("index.ejs");
});

app.get("/register", checkNotAuthenticated, (req, res) => {
  res.render("register.ejs");
});

app.get("/login", checkNotAuthenticated, (req, res) => {
  res.render("login.ejs");
});

app.post("/register", checkNotAuthenticated, async (req, res) => {
  const hashedPassword = await bcrypt.hash(req.body.password, 10);

  users.push({
    id: Date.now().toString(),
    name: req.body.name,
    email: req.body.email,
    password: hashedPassword,
  });

  res.redirect("/login");
});

app.post(
  "/login",
  checkNotAuthenticated,
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
    failureFlash: true,
  })
);

module.exports = app;
