import express from "express";
import { connection } from "./src/models/db.js";
import bcryptjs from "bcryptjs";
import jwt from "jsonwebtoken";
import { promisify } from "util";

const JWT_SECRET = "1234";
const JWT_EXPIRES_IN = "90d";
const JWT_COOKIE_EXPIRES = "90";

const app = express();
const port = 3000;

app.use(express.json());
app.use(
  express.urlencoded({
    extended: false,
  })
);

app.get("/", (req, res) => {
  res.json({ message: "ok" });
});

app.post("/register", (req, res) => {
  const { email, username, password, confirm_password } = req.body;
  if (!email || !username || !password || !confirm_password) {
    return res.status(400).send("Please enter all fields!");
  }
  connection.query(
    "SELECT email FROM users WHERE email=?",
    [email],
    async (err, result) => {
      if (err) {
        res.json(err);
      }

      if (result.length > 0) {
        res.send("Email already taken!");
      } else if (password !== confirm_password) {
        res.send("Password should be matched with confirm passowrd");
      } else {
        const encrypted_password = await bcryptjs.hash(password, 8);
        connection.query(
          "INSERT INTO users set ?",
          {
            email,
            username,
            password: encrypted_password,
          },
          (error, result) => {
            if (error) {
              res.json(error);
            } else {
              res.json({ message: "Registration Success!" });
            }
          }
        );
      }
    }
  );
});

app.post("/login", (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).send("Please enter your Email and Password");
    }

    connection.query(
      "SELECT * FROM users WHERE email=?",
      [email],
      async (error, result) => {
        console.log(result);
        if (result <= 0) {
          return res.status(401).send("Please email and password");
        } else {
          if (!(await bcryptjs.compare(password, result[0].password))) {
            return res.status(401).send("Email or Password Incorrect");
          } else {
            const id = result[0].id;
            const token = jwt.sign({ id }, JWT_SECRET, {
              expiresIn: JWT_EXPIRES_IN,
            });
            // console.log(token);
            res.json({
              email: result[0].email,
              username: result[0].username,
              access_token: token,
              token_expires: JWT_COOKIE_EXPIRES * 20 * 60 * 1000,
            });
          }
        }
      }
    );
  } catch (error) {
    res.json(error);
  }
});

app.post("/check_token", async (req, res) => {
  const { access_token } = req.body;

  if (!access_token) {
    return res.send("Please add token");
  }

  try {
    const decode = await promisify(jwt.verify)(access_token, JWT_SECRET);

    connection.query(
      "SELECT * FROM users WHERE id=?",
      [decode.id],
      (error, result) => {
        if (error) {
          return res.json(error);
        }

        const { id, email, username } = result[0];
        res.json({ id, email, username, access_token });
      }
    );
  } catch (error) {
    res.status(401).json({ message: "Invalid Token" });
  }
});

app.get("/products", (req, res) => {
  connection.query("SELECT * FROM products", (err, rows) => {
    if (err) {
      res.json(err);
    } else {
      res.json(rows);
    }
  });
});

app.post("/order", (req, res) => {
  const { title, image, price, user_id } = req.body;
  if (!title || !image || !price || !user_id) {
    return res.status(401).json({ message: "Please enter all fields!" });
  }

  connection.query(
    "INSERT INTO orders set ?",
    { title, image, price, user_id },
    (error, result) => {
      if (error) {
        res.json(error);
      } else {
        res.json({ message: "Order Placed Successfully!" });
      }
    }
  );
});

app.post("/my_orders", (req, res) => {
  const { user_id } = req.body;
  connection.query(
    "SELECT * FROM orders WHERE user_id=?",
    [user_id],
    async (error, result) => {
      res.status(200).json(result);
    }
  );
});

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});
