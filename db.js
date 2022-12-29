var sqlite3 = require('sqlite3');
var mkdirp = require('mkdirp');

mkdirp.sync('var/db');

var db = new sqlite3.Database('./var/db/demo.db');

db.serialize(function() {
  db.run("CREATE TABLE IF NOT EXISTS users ( \
    id INTEGER PRIMARY KEY AUTOINCREMENT, \
    username TEXT, \
    email TEXT UNIQUE, \
    email_verified INTEGER, \
    hashed_password BLOB, \
    salt BLOB, \
    status INTEGER, \
    sign_up_at TEXT, \
    last_login_at TEXT, \
    login_times, \
    created_at TEXT, \
    updated_at TEXT \
  )");
  
  db.run("CREATE TABLE IF NOT EXISTS federated_credentials ( \
    user_id INTEGER NOT NULL, \
    provider TEXT NOT NULL, \
    subject TEXT NOT NULL, \
    PRIMARY KEY (provider, subject) \
  )");

  db.run("CREATE TABLE IF NOT EXISTS active_logs ( \
    user_id INTEGER NOT NULL, \
    login_at TEXT \
  )");
});

module.exports = db;