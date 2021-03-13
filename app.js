//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const app = express();
const encrypt = require("mongoose-encryption");
const md5 = require("md5");
const bcrypt = require("bcrypt");
const saltRounds = 10;
const session = require("express-session");
const passport = require("passport");
const passportlocalmongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');


app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(
    express.urlencoded({
        extended: true,
    })
);

app.use(
    session({
        secret: "our little secret",
        resave: false,
        saveUninitialized: true,
    })
);

app.use(passport.initialize());



app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
});

userSchema.plugin(passportlocalmongoose);
userSchema.plugin(findOrCreate);
//userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });
  


passport.use(new GoogleStrategy({
        clientID: process.env.CLIENT_ID,
        clientSecret: process.env.CLINET_SECRET,
        callbackURL: "http://localhost:3000/auth/google/secrets",
        userProfileURL: "https://googleapis.com/oauth2/v3/userinfo"
    },
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({
            googleId: profile.id
        }, function (err, user) {
            return cb(err, user);
        });
    }
));


app.get("/", function (req, res) {
    res.render("home");
});

app.get("/login", function (req, res) {
    res.render("login");
});

app.get("/register", function (req, res) {
    res.render("register");
});

//Using normal settings

/* app.post("/register", function (req, res) {


    bcrypt.genSalt(saltRounds, function (err, salt) {
        bcrypt.hash(req.body.password, salt, function (err, hash) {

            const Newuser = new User({
                email: req.body.username,
                password: hash
            });

            Newuser.save(function (err) {
                if (err) {
                    console.log(err);
                } else {
                    res.render("secrets");
                }
            });

            // Store hash in your password DB.
        });
    });

}); */

// post request with passport



app.get("/secrets", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("secrets");
    } else {
        res.redirect("/login");
    }


})


app.post("/register", function (req, res) {
    User.register({
            username: req.body.username
        },
        req.body.password,
        function (err, user) {
            if (err) {
                s
                res.redirect("/register");
            } else {
                passport.authenticate("local")(req, res, function () {
                    res.redirect("/secrets");
                });
            }
        }
    );
});




app.post("/login", function (req, res) {


    const user = ({

        username: req.body.username,
        password: req.body.password
    })


    req.logIn(user, function (err) {
        if (err) {

            console.log(err);
        } else {

            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            });
        }

    });



});


app.get("/logout", function (req, res) {

    req.logout();
    res.redirect("/");

});


app.get('/auth/google',
    passport.authenticate('google', {
        scope: ["profile"]
    }));



    app.get("/auth/google/secrets", 
    passport.authenticate("google", { failureRedirect: '/login' }),
    function(req, res) {
      // Successful authentication, redirect secrets.
      res.redirect('/secrets');
    });
  



app.listen(3000, function () {
    console.log("Listening to port 3000");
});