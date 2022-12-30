require("dotenv").config();

var path = require("path");
var express = require("express");
var passport = require("passport");
var session = require("express-session");
var authRouter = require("./routes/auth");
var indexRouter = require("./routes/index");
var expressLayouts = require("express-ejs-layouts");
var swaggerUi = require('swagger-ui-express');
var swaggerDocument = require('./swagger.json');

var app = express();

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// 登入使用的 session
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true
  })
);

app.use(express.urlencoded({ extended: false }))
app.use(expressLayouts);
app.use(passport.initialize());
app.use(passport.session());

// global middleware to check user logged in status
app.use(function (req, res, next) {
  if (req.isAuthenticated()) {
    res.locals.user = req.session.passport.user;
  }
  return next();
});
app.use("/", indexRouter);
app.use("/", authRouter);

app.set("views", path.join(__dirname, "views"));
app.set("layout", "./layouts/layout");
app.set("view engine", "ejs");

app.all("*", checkUser);

function checkUser(req, res, next) {
  if (req.isAuthenticated()) {
    res.locals.user = req.session.passport.user;
  }
  return next();
}

app.listen("3000", () => {});
