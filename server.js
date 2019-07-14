const ENV = process.env;
const express = require('express');
const flash = require('connect-flash');
const passport = require('passport');
const Strategy = require('passport-local').Strategy;
const mysql = require("mysql");
const crypto = require('crypto');

const MYSQL_HOST = ENV.MYSQL_HOST || "localhost";
const MYSQL_DB = ENV.MYSQL_DB;
const MYSQL_USER = ENV.MYSQL_USER;
const MYSQL_PASSWORD = ENV.MYSQL_PASSWORD;
const MYSQL_USER_TABLE = ENV.MYSQL_USER_TABLE;

const connection = mysql.createConnection({
  host: MYSQL_HOST,
  user: MYSQL_USER,
  password: MYSQL_PASSWORD
});

connection.query("USE " + MYSQL_DB);

// Hashing algorithm. Replace with any other support algorithm.
function sha512(data) {
  return crypto.createHash('sha512').update(data, 'utf-8').digest('hex');
}

// MySQL User Signup via named 'local-signup 'strategy
passport.use(
  "local-signup",
  new Strategy(
    {
      usernameField: "username",
      passwordField: "password",
      passReqToCallback: true // allows us to pass back the entire request to the callback
    },
    function(req, username, password, done) {;
      password = sha512(password);
      // Find a user whose username is the same as the forms username
      // Check to see if the user trying to login already exists
      connection.query(
        "select * from " + MYSQL_USER_TABLE + " where username = '" + username + "'",
        function(err, rows) {
          if (err) return done(err);
          if (rows.length) {
            return done(
              null,
              false,
              req.flash("signupMessage", "That username is already taken.")
            );
          } else {
            // Create the user if there is no user with that username
            var newUserMysql = new Object();

            newUserMysql.username = username;
            newUserMysql.password = password; // use the generateHash function in our user model

            var insertQuery =
              "INSERT INTO " + MYSQL_USER_TABLE + " ( username, password ) values ('" +
              username +
              "','" +
              password +
              "')";

            connection.query(insertQuery, function(err, rows) {
              newUserMysql.id = rows.insertId;

              return done(null, newUserMysql);
            });
          }
        }
      );
    }
  )
);

//MySQL User Login via named 'local-login 'strategy
passport.use(
  "local-login",
  new Strategy(
    {
      usernameField: "username",
      passwordField: "password",
      passReqToCallback: true
    },
    function(req, username, password, done) {
      connection.query(
        "SELECT * FROM " + MYSQL_USER_TABLE + " WHERE `username` = '" + username + "'",
        function(err, rows) {
          if (err) return done(err);
          if (!rows.length) {
            return done(
              null,
              false,
              req.flash("loginMessage", "No user found.")
            );
          }
          password = sha512(password);
          if (!(rows[0].password == password)) {
            return done(
              null,
              false,
              req.flash("loginMessage", "Oops! Wrong password.")
            );
          }
          return done(null, rows[0]);
        }
      );
    }
  )
);

// Passport session
// Required for persistent login sessions
// Serialize the user for the session
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

// Deserialize the user
passport.deserializeUser(function(id, done) {
  connection.query("select * from " + MYSQL_USER_TABLE + " where id = " + id, function(
    err,
    rows
  ) {
    done(err, rows[0]);
  });
});

// Create a new Express application
var app = express();

// Configure view engine to render EJS templates
app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');

// Use application-level middleware for common functionality, including
// logging, parsing, and session handling
app.use(require('morgan')('combined'));
app.use(require('body-parser').urlencoded({ extended: true }));
app.use(require('express-session')({ secret: 'keyboard cat', resave: false, saveUninitialized: false }));
app.use(flash());

// Initialize Passport and restore authentication state, if any, from the session
app.use(passport.initialize());
app.use(passport.session());

// Define applcation routes
app.get('/',
  function(req, res) {
    res.render('home', { user: req.user });
  });

app.get('/login',
  function(req, res){
    res.render('login');
  });

app.post('/login',
  passport.authenticate('local-login', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/');
  });

app.get('/signup',
  function(req, res){
    res.render('signup');
  });

app.post('/signup',
  passport.authenticate('local-signup', { failureRedirect: '/signup' }),
  function(req, res) {
    res.redirect('/');
  });

app.get('/logout',
  function(req, res){
    req.logout();
    res.redirect('/');
  });

app.get('/profile',
  require('connect-ensure-login').ensureLoggedIn(),
  function(req, res){
    res.render('profile', { user: req.user });
  });

app.listen(3000);
