"use strict";
require("dotenv").config();
const express = require("express");
const myDB = require("./connection");
const fccTesting = require("./freeCodeCamp/fcctesting.js");
const session = require("express-session");
const passport = require("passport");
const routes = require("./routes.js");
const auth = require("./auth.js");
const passportSocketIo = require("passport.socketio");
const cookieParser = require("cookie-parser");
const connect = require("mongodb");
const { connected } = require("process");

const app = express();

const http = require("http").createServer(app);
const io = require("socket.io")(http);

const MongoStore = require("connect-mongo")(session);
const URI = process.env.MONGO_URI;
const store = new MongoStore({ url: URI });

fccTesting(app); //For FCC testing purposes
app.use("/public", express.static(process.cwd() + "/public"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: true,
    saveUninitialized: true,
    cookie: { secure: false, sameSite: "lax" },
    key: "express.sid",
    store: store,
  })
);

app.set("view engine", "pug");
app.set("views", "./views/pug");

app.use(passport.initialize());
app.use(passport.session());

io.use(
  passportSocketIo.authorize({
    cookieParser: cookieParser,
    key: "express.sid",
    secret: process.env.SESSION_SECRET,
    store: store,
    success: onAuthorizeSuccess,
    fail: onAuthorizeFail,
  })
);

myDB(async (client) => {
  const myDatabase = await client.db("test").collection("users-fcc");

  routes(app, myDatabase);
  auth(app, myDatabase);

  let currentUsers = 0;

  io.on("connection", (socket) => {
    ++currentUsers;
    const username = socket?.request?.user?.username || "Anonymous";

    io.emit("user", {
      username,
      currentUsers,
      connected: true,
    });
    console.log("A user has connected");

    socket.on("disconnect", () => {
      --currentUsers;
      io.emit("user", {
        username,
        currentUsers,
        connected: false,
      });
      console.log("A user has disconnected");
    });

    socket.on("chat message", (message) => {
      io.emit("chat message", {
        username,
        message,
      });
    });
  });
}).catch((e) => {
  app.route("/").get((req, res) => {
    res.render("index", {
      title: e,
      message: "Unable to connect to database",
    });
  });
});

function onAuthorizeSuccess(data, accept) {
  console.log("successful connection to socket.io");

  accept(null, true);
}

function onAuthorizeFail(data, message, error, accept) {
  if (error) throw new Error(message);
  console.log("failed connection to socket.io:", message);
  accept(null, false);
}

const PORT = process.env.PORT || 3000;
http.listen(PORT, () => {
  console.log("Listening on port " + PORT);
});
