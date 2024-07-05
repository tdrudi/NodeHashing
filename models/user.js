/** User class for message.ly */
const db = require("../db");
const bcrypt = require("bcrypt");
const ExpressError = require("../expressError");
const {BCRYPT_WORK_FACTOR} = require("../config");


/** User of the site. */

class User {

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({username, password, first_name, last_name, phone}) {
    let hashPass = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
    
    const res = await db.query(`INSERT INTO users (username, password, first_name, last_name, phone, join_at, last_login_at) 
      VALUES($1, $2, $3, $4, $5, current_timestamp, current_timestamp) 
      RETURNING username, password, first_name, last_name, phone`, 
      [username, hashPass, first_name, last_name, phone]);
    
      return res.rows[0];
  }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    const res = await db.query(`SELECT password FROM users WHERE username = $1`, [username]);
    let user = res.rows[0];
    checkUser = await bcrypt.compare(password, user.password);
    return checkUser;
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    const res = await db.query(`UPDATE users SET last_login_at = current_timestamp 
      WHERE username = $1 RETURNING username`, 
      [username]);
    
    if(!res.rows[0])
      throw new ExpressError(`User does not exist: ${username}`, 404);
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    const res = await db.query(`SELECT username, first_name, last_name, phone FROM users ORDER BY username`);
    return res.rows;
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) {
    const res = await db.query(`SELECT username, first_name, last_name, phone, join_at, last_login_at
      FROM users WHERE username = $1`, [username]);
    
    if(!res.rows[0])
      throw new ExpressError(`User does not exist: ${username}`, 404);
    
    return res.rows[0];
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {
    const res = db.query(`SELECT messages.id, messages.to_username, users.first_name, users.last_name, users.phone, messages.body, messages.sent_at, messages.read_at
      FROM messages JOIN users ON messages.to_username = users.username WHERE from_username = $1`, [username]);

    return res.rows.map(messages => ({
      id: messages.id,
      to_user: {
        username: messages.to_username,
        first_name: messages.first_name,
        last_name: messages.last_name,
        phone: messages.phone
      },
      body: messages.body,
      sent_at: messages.sent_at,
      read_at: messages.read_at,
    }));

  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) {
    const res = db.query(`SELECT messages.id, messages.from_username, users.first_name, users.last_name, users.phone, messages.body, messages.sent_at, messages.read_at
      FROM messages JOIN users ON messages.from_username = users.username WHERE to_username = $1`, [username]);

    return res.rows.map(messages => ({
      id: messages.id,
      from_user: {
        username: messages.from_username,
        first_name: messages.first_name,
        last_name: messages.last_name,
        phone: messages.phone
      },
      body: messages.body,
      sent_at: messages.sent_at,
      read_at: messages.read_at,
    }));
  }
}


module.exports = User;