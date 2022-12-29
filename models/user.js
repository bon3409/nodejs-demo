var db = require("../db");
var helper = require("../helper/helper");
var bcrypt = require("bcrypt");

module.exports = {
  getUser: function (email) {
    return new Promise((resolve, reject) => {
      db.serialize(() => {
        db.get("SELECT * FROM users WHERE email = ?", [email], (err, rows) => {
          if (err) reject(err);
          resolve(rows);
        });
      });
    });
  },

  setPassword: function (email, password) {
    return new Promise((resolve, reject) => {
      db.serialize(() => {
        var hashed_password = bcrypt.hashSync(password, 10);
        db.run(
          "UPDATE users SET hashed_password = ? WHERE email = ?",
          [hashed_password, email],
          (err, rows) => {
            if (err) reject(err);
            resolve(rows);
          }
        );
      });
    });
  },

  comparePwd: function (password, checkPassword) {
    return new Promise((resolve, reject) => {
      if (bcrypt.compare(password, checkPassword)) {
        return reject();
      } else {
        resolve();
      }
    });
  },

  updateUserName: function (id, username) {
    return new Promise((resolve, reject) => {
      db.serialize(() => {
        db.run(
          "UPDATE users SET username = ? WHERE id = ?",
          [username, id],
          (err, row) => {
            if (err) {
              reject(err);
            }
            resolve(row);
          }
        );
      });
    });
  },

  getUsers: function () {
    return new Promise((resolve, reject) => {
      db.serialize(() => {
        db.all(
          "SELECT id, username, email, sign_up_at, last_login_at, login_times FROM users;",
          [],
          (err, rows) => {
            if (err) reject(err);
            resolve(rows);
          }
        );
      });
    });
  },

  getUserStatics: function () {
    return new Promise((resolve, reject) => {
      db.serialize(() => {
        db.get("SELECT SUM");
      });
    });
  },

  activeLog: function (userId) {
    return new Promise((resolve, reject) => {
      var now = new Date().getTime();
      var dateTime = helper.coverTimeFormat(now);
      db.serialize(() => {
        db.run(
          "INSERT INTO active_logs (user_id, login_at) VALUES (?, ?)",
          [userId, dateTime],
          (err, row) => {
            if (err) {
              reject(err);
            }
            resolve(row);
          }
        );
      });
    });
  },

  findFederated: function (profile) {
    return new Promise((resolve, reject) => {
      db.serialize(() => {
        db.get("SELECT * FROM federated_credentials WHERE provider = ? AND subject = ?", [profile.provider, profile.id], (err, row) => {
          if (err) { reject(err); }
          resolve(row);
        });
      });
    });
  },

  createSsoUser: function (username) {
    return new Promise((resolve, reject) => {
      var now = new Date().getTime();
      var dateTime = helper.coverTimeFormat(now);
      db.serialize(() => {
        db.run("INSERT INTO users (username, login_times, sign_up_at, last_login_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        [username, 1, dateTime, dateTime, dateTime, dateTime], function (err) {
          if (err) { reject(err); }
          resolve(this.lastID);
        });
      });
    });
  },

  createFederate: function(userId, profile) {
    return new Promise((resolve, reject) => {
      db.serialize(() => {
        db.run("INSERT INTO federated_credentials (user_id, provider, subject) VALUES (?, ?, ?)", [userId, profile.provider, profile.id], (err) => {
          if (err) { reject(err); }
          var user = {
            id: userId,
            username: profile.displayName
          }

          return resolve(user);
        });
      });
    });
  },

  updateLoginAt: function (userId) {
    return new Promise((resolve, reject) => {
      var now = new Date().getTime();
      var dateTime = helper.coverTimeFormat(now);
      db.serialize(() => {
        db.run("UPDATE users SET last_login_at = ?, updated_at = ?, login_times = login_times +1 WHERE id = ?", [dateTime, dateTime, userId], (err) => {
          if (err) { reject(err); }
          resolve();
        });
      });
    });
  },

  getUserById: function (userId) {
    return new Promise((resolve, reject) => {
      db.serialize(() => {
        db.get("SELECT * FROM users WHERE id = ?", [userId], (err, row) => {
          if (err) { reject(err); }
          if (!row) { reject(null); }
          resolve(row);
        });
      });
    });
  },

  getStatistics: function () {
    return new Promise((resolve, reject) => {
      var sql = "SELECT SUM(login_times) as 'login_times_total', (SELECT COUNT(*) FROM users WHERE last_login_at > date('now', 'start of day')) AS 'active_total', (SELECT COUNT(*) / 7 FROM active_logs WHERE login_at > date('now', '-7 days')) AS 'average' FROM users;"
      db.serialize(() => {
        db.get(sql, [], (err, row) => {
          if (err) { reject(err); }
          resolve(row);
        })
      })
    })
  }
};
