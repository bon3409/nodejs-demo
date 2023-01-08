const express = require("express");

let router = express.Router();

// index page
router.get("/", function (req, res) {
  res.render("index");
});

router.get("/login", function (req, res) {
  if (req.isAuthenticated()) {
    return res.redirect("/");
  }
  res.render("./pages/login");
});

router.get("/register", function (req, res) {
  res.render("./pages/register");
});

router.get("/register-password", function (req, res) {
  if (!req.isAuthenticated()) {
    return res.redirect("./login");
  }

  if (req.session.passport.user.hashed_password) {
    return res.redirect("/dashboard");
  }

  res.render("./pages/register-password");
});

router.get("/reset-password", function (req, res) {
  if (!req.isAuthenticated()) {
    return res.redirect("./login");
  }

  if (!req.session.passport.user.hashed_password) {
    return res.redirect("/register-password");
  }

  res.render("./pages/reset-password");
});

router.get("/forget-password", function (req, res) {
  res.render("./pages/forget-password");
});

router.get("/error", function (req, res) {
  res.render("./pages/error");
});

module.exports = router;
