"use strict";
require("dotenv").config();
const express = require("express");
const myDB = require("./connection");
const fccTesting = require("./freeCodeCamp/fcctesting.js");
const session = require("express-session");
const passport = require("passport");
const { ObjectId } = require("mongodb");

const app = express();

fccTesting(app); //For FCC testing purposes
app.use("/public", express.static(process.cwd() + "/public"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: true,
    saveUninitialized: true,
    cookie: { secure: false },
  })
);

app.set("view engine", "pug");
app.set("views", "./views/pug");

passport.initialize();
passport.session();

myDB(async (client) => {
  const myDatabase = await client.db("test").collection("users-fcc");

  app.route("/").get((req, res) => {
    res.render("index", {
      title: "Connected to Database",
      message: "Please log in",
    });

    passport.serializeUser((user, done) => {
      done(null, user._id);
    });

    passport.deserializeUser((id, done) => {
      myDatabase.findOne({ _id: new ObjectId(id) }, (err, doc) => {
        done(null, doc);
      });
    });
  });
}).catch((e) => {
  app.route("/").get((req, res) => {
    res.render("index", { title: e, message: "Unable to connect to database" });
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Listening on port " + PORT);
});
