require("dotenv").config();

let path = require("path");
let express = require("express");
let passport = require("passport");
let session = require("express-session");
let authRouter = require("./routes/auth");
let indexRouter = require("./routes/index");
let expressLayouts = require("express-ejs-layouts");
let swaggerUi = require('swagger-ui-express');
let swaggerDocument = require('./swagger.json');

let app = express();

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
