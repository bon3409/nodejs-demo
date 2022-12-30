var express = require("express");
var passport = require("passport");
var bcrypt = require("bcrypt");
var passwordValidator = require("password-validator");
var GoogleStrategy = require("passport-google-oauth2").Strategy;
var FacebookStrategy = require("passport-facebook").Strategy;
var MagicLinkStrategy = require("passport-magic-link").Strategy;
var LocalStrategy = require("passport-local").Strategy;

const bodyParser = require("body-parser");
const nodemailer = require("nodemailer");
var app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
var schema = new passwordValidator();
schema
  .is()
  .min(8, "Password contains at least 8 characters.") // Minimum length 8
  .has()
  .uppercase(1, "Password contains at least one upper character.") // Must have uppercase letters
  .has()
  .lowercase(1, "Password contains at least one lower character.") // Must have lowercase letters
  .has()
  .digits(1, "Password contains at least one digit character.") // Must have at least 1 digits
  .has()
  .not()
  .spaces() // Should not have spaces
  .has()
  .symbols(1, "Password contains at least one special character."); // special characters

var helper = require("../helper/helper");
var db = require("../db");
var userModel = require("..//models/user");

// gmail setting
const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  auth: {
    type: "OAuth2",
    user: process.env.MAIL_ACCOUNT,
    clientId: process.env.MAIL_CLIENT_ID,
    clientSecret: process.env.MAIL_CLIENT_SECRET,
    refreshToken: process.env.MAIL_REFRESHTOKEN,
    accessToken: process.env.MAIL_ACCESS_TOKEN,
  },
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
      scope: ["profile"],
    },
    async function verify(request, accessToken, refreshToken, profile, done) {
      var now = new Date().getTime();
      var dateTime = helper.coverTimeFormat(now);
      var federateRecord = await userModel.findFederated(profile);

      if (!federateRecord) {
        var userId = await userModel.createSsoUser(
          profile.displayName,
          dateTime
        );

        if (!userId) {
          return done(null);
        }

        await userModel.activeLog(userId);
        var user = await userModel.createFederate(userId, profile);
        done(null, user);
      } else {
        await userModel.updateLoginAt(federateRecord.user_id);
        await userModel.activeLog(federateRecord.user_id);
        var user = await userModel.getUserById(federateRecord.user_id);
        done(null, user);
      }
    }
  )
);

passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_CLIENT_ID,
      clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
      callbackURL: process.env.FACEBOOK_CALLBACK_URL,
    },
    async function verify(request, accessToken, refreshToken, profile, done) {
      var federateRecord = await userModel.findFederated(profile);

      if (!federateRecord) {
        var userId = await userModel.createSsoUser(profile.displayName);

        if (!userId) {
          return done(null);
        }

        await userModel.activeLog(userId);
        var user = await userModel.createFederate(userId, profile);
        done(null, user);
      } else {
        await userModel.updateLoginAt(federateRecord.user_id);
        await userModel.activeLog(federateRecord.user_id);
        var user = await userModel.getUserById(federateRecord.user_id);
        done(null, user);
      }
    }
  )
);

passport.use(
  new LocalStrategy(
    {
      usernameField: "email",
    },
    async function verify(username, password, done) {
      user = await userModel.getUser(username);

      if (!user) {
        return done(null, false, { message: "Account not exists!" });
      }

      try {
        if (await bcrypt.compare(password, user.hashed_password)) {
          var err = await userModel.updateLoginAt(user.id);

          if (err) {
            return done(err);
          }

          await userModel.activeLog(user.id);

          var user = await userModel.getUserById(user.id);

          if (!user) {
            return done(null, false);
          } else {
            return done(null, user);
          }
        } else {
          return done(null, false, { message: "password incorrect" });
        }
      } catch (e) {
        return done(e);
      }
    }
  )
);

passport.use(
  "register",
  new MagicLinkStrategy(
    {
      secret: process.env.MAGICLINKSTRATEGYSECRET,
      userFields: ["email", "username"],
      tokenField: "token",
      verifyUserAfterToken: true,
    },
    function send(user, token) {
      var link = process.env.APP_URL + "/register/email/verify?token=" + token;

      return transporter.sendMail({
        from: "demo@example.com",
        to: user.email,
        subject: "Sign in to " + process.env.APP_NAME,
        text:
          "Hello! Click the link below to finish signing in to " +
          process.env.APP_NAME +
          ".\r\n\r\n" +
          link,
        html:
          "<h3>Hello!</h3><p>Click the link below to finish signing in to " +
          process.env.APP_NAME +
          '.</p><p><a href="' +
          link +
          '">Sign in</a></p>',
      });
    },
    async function verify(user) {
      var tempUser = await userModel.getUser(user.email);
      if (!tempUser) {
        var userId = await userModel.createUser(user.username, user.email);
        user = await userModel.getUserById(userId);
      } else {
        user = tempUser;
      }

      await userModel.activeLog(user.id);
      return user;
    }
  )
);

passport.use(
  "forget-password",
  new MagicLinkStrategy(
    {
      secret: process.env.MAGICLINKSTRATEGYSECRET,
      userFields: ["email"],
      tokenField: "token",
      verifyUserAfterToken: true,
    },
    function send(user, token) {
      var link = process.env.APP_URL + "/forget-password/verify?token=" + token;

      return transporter.sendMail({
        from: "demo@example.com",
        to: user.email,
        subject: "Forget password in " + process.env.APP_NAME,
        text:
          "Hello! Click the link below to reset your password in to " +
          process.env.APP_NAME +
          ".\r\n\r\n" +
          link,
        html:
          "<h3>Hello!</h3><p>Click the link below to reset your password in to " +
          process.env.APP_NAME +
          '.</p><p><a href="' +
          link +
          '">Reset password</a></p>',
      });
    },
    function verify(user) {
      return new Promise(function (resolve, reject) {
        db.get(
          "SELECT * FROM users WHERE email = ?",
          [user.email],
          function (err, row) {
            if (err) {
              return reject(err);
            }
            if (!row) {
              reject();
            } else {
              return resolve(row);
            }
          }
        );
      });
    }
  )
);

passport.serializeUser(function (user, done) {
  done(null, user);
});

passport.deserializeUser(function (user, done) {
  done(null, user);
});

var router = express.Router();

// middleware: check user is login or not
function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) {
    req.isLogged = true;
    return next();
  }
  return res.redirect("/login");
}

// redirect to google login
router.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

// google auth callback
router.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    successRedirect: "/dashboard",
    failureRedirect: "/auth/failure",
  })
);

// redirect to facebook login
router.get("/auth/facebook", passport.authenticate("facebook"));

// facebook auth callback
router.get(
  "/auth/facebook/callback",
  passport.authenticate("facebook", {
    successRedirect: "/dashboard",
    failureRedirect: "/auth/failure",
  })
);

// only login success will into this route
router.get("/dashboard", isLoggedIn, async (req, res) => {
  var username = req.user.username ?? req.user.displayName;
  var users = await userModel.getUsers();
  var statistics = await userModel.getStatistics();
  res.render("./pages/dashboard", {
    username: username,
    users: users,
    statistics: statistics,
  });
});

// profile page
router.get("/profile", isLoggedIn, (req, res) => {
  var username = req.user.username ?? req.user.displayName;
  var email = req.user.email;
  res.render("./pages/profile", {
    id: req.user.id,
    username: username,
    email: email,
  });
});

// if login fail
router.get("/auth/failure", (req, res) => {
  res.send("<h1>Unauthorized</h1>");
});

// logout
router.get("/logout", (req, res) => {
  req.logout();
  res.locals.user = null;
  res.render("./pages/logout", { layout: "./layouts/layout" });
});

// email / password login
router.post(
  "/auth/login",
  passport.authenticate("local", {
    successRedirect: "/dashboard",
    failureRedirect: "/login",
  })
);

// email / password register
router.post(
  "/register/email",
  passport.authenticate("register", {
    action: "requestToken",
    failureRedirect: "/register",
  }),
  function (req, res, next) {
    res.redirect("/register/email/check");
  }
);

router.get("/register/email/check", function (req, res, next) {
  res.render("./pages/email-check");
});

router.get(
  "/register/email/verify",
  passport.authenticate("register", {
    successReturnToOrRedirect: "/register-password",
    failureRedirect: "/register",
  })
);

router.post("/register-password", async function (req, res, next) {
  var user = req.session.passport.user;

  if (!user) {
    return res.redirect("/register");
  }

  var validator = schema.validate(req.body.password, { details: true });
  if (validator.length > 0) {
    return res.render("./pages/register-password", {
      message: validator[0]["message"],
    });
  }

  if (req.body.password != req.body.check_password) {
    return res.render("./pages/register-password", {
      message: "Password is different",
    });
  }

  await userModel.setPassword(user.email, req.body.password);
  var user = await userModel.getUser(user.email);
  req.session.passport.user = user;

  return res.redirect("/dashboard");
});

// forget password
router.post(
  "/forget-password",
  passport.authenticate("forget-password", {
    action: "requestToken",
    failureRedirect: "/error",
  }),
  function (req, res, next) {
    res.redirect("/forget-password/email/check");
  }
);

router.get("/forget-password/email/check", function (req, res, next) {
  res.render("./pages/forget-password-check");
});

router.get(
  "/forget-password/verify",
  passport.authenticate("forget-password", {
    successReturnToOrRedirect: "/forget-password/reset",
    failureRedirect: "/error",
  })
);

// forget password to reset
router.get("/forget-password/reset", function (req, res) {
  res.render("./pages/forget-password-reset");
});

router.post("/forget-password/reset", async function (req, res) {
  var user = req.session.passport.user;

  if (!user) {
    return res.redirect("/register");
  }

  var validator = schema.validate(req.body.password, { details: true });
  if (validator.length > 0) {
    return res.render("./pages/register-password", {
      message: validator[0]["message"],
    });
  }

  if (req.body.password != req.body.check_password) {
    return res.render("./pages/forget-password-reset", {
      message: "Password is different!",
    });
  }

  await userModel.setPassword(user.email, req.body.password);
  var user = await userModel.getUser(user.email);
  req.session.passport.user = user;

  req.logout();
  res.locals.user = null;
  return res.redirect("/login");
});

// reset password
router.post("/reset-password", function (req, res, next) {
  var user = req.session.passport.user;

  // verify old password
  if (!bcrypt.compareSync(req.body.old_password, user.hashed_password)) {
    return res.render("./pages/reset-password", {
      errorMessage: "Old password is incorrect!",
    });
  }

  var validator = schema.validate(req.body.new_password, { details: true });
  if (validator.length > 0) {
    return res.render("./pages/reset-password", {
      errorMessage: validator[0]["message"],
    });
  }

  // confirm new password
  if (req.body.new_password != req.body.check_password) {
    return res.render("./pages/reset-password", {
      errorMessage: "Password is different!",
    });
  }

  var user = userModel.setPassword(user.email, req.body.new_password);

  return res.render("./pages/reset-password", {
    message: "Password reset success!",
  });
});

router.post("/profile", function (req, res) {
  userModel.updateUserName(req.body.id, req.body.username);
  req.session.passport.user.username = req.body.username;
  var id = req.session.passport.user.id;
  var email = req.session.passport.user.email;
  res.render("./pages/profile", {
    id: id,
    username: req.body.username,
    email: email,
    message: "Save successfully",
  });
});

module.exports = router;
