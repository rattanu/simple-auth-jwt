const cors = require("cors");
const express = require("express");
const mysql = require("mysql2/promise");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const bcrypt = require("bcrypt");

const app = express();
app.use(express.json());
app.use(
  cors({
    credentials: true,
    origin: "*",
  })
);
app.use(cookieParser());

app.use(
  session({
    secret: "secret",
    resave: false,
    saveUninitialized: true,
  })
);

const port = 8000;
const secret = "mysecret";

let conn = null;

// function init connection mysql
const initMySQL = async () => {
  conn = await mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "root",
    database: "tutorial",
  });
};

/* เราจะแก้ไข code ที่อยู่ตรงกลาง */
app.post("/api/register", async (req, res) => {
  try {
    const { email, password, role = "user" } = req.body; // กำหนดค่าเริ่มต้นของ role เป็น 'user'

    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Please provide both email and password" });
    }

    const hash = await bcrypt.hash(password, 10);
    const userData = { email, password: hash, role };

    const result = await conn.query("INSERT INTO users SET ?", userData);
    res.json({ message: "Insert ok", result });
  } catch (error) {
    console.error(error);
    if (error.code === "ER_DUP_ENTRY") {
      return res.status(400).send("Email is already registered");
    }
    return res.status(400).json({ message: "Insert fail", error });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // ดึงข้อมูลผู้ใช้จากฐานข้อมูล
    const [result] = await conn.query(
      "SELECT * FROM users WHERE email = ?",
      email
    );
    const user = result[0];

    // ตรวจสอบรหัสผ่าน
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).send({ message: "Invalid email or password" });
    }

    // ดึง role ของผู้ใช้จากฐานข้อมูล
    const role = user.role;

    // สร้าง JWT token พร้อมกับ email และ role
    const token = jwt.sign({ email, role }, secret, { expiresIn: "1h" });

    res.json({
      message: "Login success",
      token,
    });
  } catch (error) {
    console.error(error);
    res.status(401).json({
      message: "Login fail",
      error,
    });
  }
});

app.get("/api/users", async (req, res) => {
  try {
    const authHeader = req.headers["authorization"];

    if (!authHeader) {
      return res.status(401).json({ message: "Missing authorization token" });
    }

    const authToken = authHeader.split(" ")[1];
    console.log("authToken :", authToken);

    const user = jwt.verify(authToken, secret);

    const [checkResults] = await conn.query(
      "SELECT * FROM users WHERE email = ?",
      user.email
    );

    if (!checkResults[0]) {
      throw { message: "User not found" };
    }

    // const [results] = await conn.query('SELECT * FROM users WHERE email = ?', user.email);
    // console.log("user :", user);
    // res.json({ users: results[0].email});
    
    // ส่งออก email และ role ของผู้ใช้ที่ login
    const email = checkResults[0].email;
    const role = checkResults[0].role;
    res.json({ email, role });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to fetch users", error });
  }
});

// Listen
app.listen(port, async () => {
  await initMySQL();
  console.log("Server started at port 8000");
});
