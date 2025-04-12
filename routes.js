const passport = require("passport");
const bcrypt = require("bcrypt");

module.exports = function (app, myDatabase) {
  app.route("/").get((req, res) => {
    res.render("index", {
      title: "Connected to Database",
      message: "Please log in",
      showLogin: true,
      showRegistration: true,
      showSocialAuth: true,
    });
  });

  app
    .route("/login")
    .post(
      passport.authenticate("local", { failureRedirect: "/" }),
      (req, res) => {
        res.redirect("/chat");
      }
    );

  app.route("/logout").get((req, res) => {
    req.logout();
    res.redirect("/");
  });

  app.route("/register").post(
    (req, res, next) => {
      const hash = bcrypt.hashSync(req.body.password, 12);
      myDatabase.findOne({ username: req.body.username }, (err, user) => {
        if (err) {
          next(err);
        } else if (user) {
          res.redirect("/");
        } else {
          myDatabase.insertOne(
            {
              username: req.body.username,
              password: hash,
            },
            (err, doc) => {
              if (err) {
                res.redirect("/");
              } else {
                myDatabase.findOne({ _id: doc.insertedId }, (err, newUser) => {
                  if (err) return next(err);
                  next(null, newUser); // pass the full user object
                });
              }
            }
          );
        }
      });
    },
    passport.authenticate("local", { failureRedirect: "/" }),
    (req, res, next) => {
      res.redirect("/chat");
    }
  );

  app.route("/auth/github").get(passport.authenticate("github"));

  app
    .route("/auth/github/callback")
    .get(
      passport.authenticate("github", { failureRedirect: "/" }),
      (req, res) => {
        req.session.user_id = req.user.id;
        res.redirect("/chat");
      }
    );

  app.route("/profile").get(ensureAuthenticated, (req, res) => {
    res.render("profile", { username: req.user.username });
  });

  app.route("/chat").get(ensureAuthenticated, (req, res) => {
    res.render("chat", { user: req.user });
  });

  app.use((req, res, next) => {
    res.status(404).type("text").send("Not Found");
  });
};

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/");
}
