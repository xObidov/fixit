const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const nodemailer = require("nodemailer");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = "your_jwt_secret";

// CORS konfiguratsiyasi (barcha metod va headerlarga ruxsat)
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "Origin", "Accept"],
  })
);

app.use(bodyParser.json());

// SQLite DB ulash
const db = new sqlite3.Database("./order.db", (err) => {
  if (err) console.error("DB ulanish xatosi:", err.message);
  console.log("SQLite ma'lumotlar bazasiga ulandi");
});

// Jadval yaratish (status ustuni bilan!)
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      email TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      role TEXT CHECK(role IN ('user', 'manager', 'fixer')) NOT NULL,
      phone TEXT
    )
  `);

db.run(`
  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER NOT NULL,
    description TEXT NOT NULL,
    phone TEXT,
    serviceTime TEXT,
    customerType TEXT,
    name TEXT,
    district TEXT,
    createdAt TEXT DEFAULT (datetime('now')),
    status TEXT DEFAULT 'pending',
    cost TEXT,
    timeon TEXT,
    userconfirm TEXT,
    userstatus TEXT DEFAULT 'waiting',
    extra TEXT           -- <<<<==== YANGI QO‘SHILGAN USTUN
  )
`);
});



// MIGRATION: orders jadvaliga ustunlar yo‘q bo‘lsa, qo‘shadi
const extraColumns = [
  { name: "cost", type: "TEXT" },
  { name: "timeon", type: "TEXT" },
  { name: "userconfirm", type: "TEXT" },
  { name: "userstatus", type: "TEXT DEFAULT 'waiting'" },
  { name: "extra", type: "TEXT" }
];

db.all("PRAGMA table_info(orders);", [], (err, columns) => {
  if (err) {
    console.error("orders jadvali tekshirilmadi:", err.message);
  } else {
    extraColumns.forEach(col => {
      const exists = columns.some(c => c.name === col.name);
      if (!exists) {
        db.run(
          `ALTER TABLE orders ADD COLUMN ${col.name} ${col.type};`,
          (err) => {
            if (err) {
              if (err.message.includes("duplicate column name")) {
                console.log(`⚠️  '${col.name}' ustuni allaqachon mavjud.`);
              } else {
                console.error(`❌ '${col.name}' ustunini qo'shishda xatolik:`, err.message);
              }
            } else {
              console.log(`✅ '${col.name}' ustuni orders jadvaliga qo'shildi!`);
            }
          }
        );
      } else {
        console.log(`ℹ️  '${col.name}' ustuni orders jadvalida allaqachon bor.`);
      }
    });
  }
});


// db.run('ALTER TABLE orders ADD COLUMN userstatus TEXT DEFAULT waiting');

// ALTER TABLE orders ADD COLUMN userstatus TEXT DEFAULT 'waiting';

// Token tekshirish middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Token mavjud emas" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Yaroqsiz token" });
    req.user = user;
    next();
  });
}

// Role tekshirish middleware
function requireRole(roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: "Ruxsat etilmagan" });
    }
    next();
  };
}

// Nodemailer konfiguratsiyasi
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "udemyread@gmail.com",
    pass: "abnk xrii pdej szmf",
  },
});

// Email yuboruvchi funksiya
const sendOrderEmail = (to, email, password, orderInfo) => {
  const mailOptions = {
    from: "udemyread@gmail.com",
    to,
    subject: "Buyurtma va login ma’lumotlari",
    text: `Assalomu alaykum!\n\nBuyurtmangiz muvaffaqiyatli qabul qilindi.\n\nLogin (email): ${email}\nParol: ${password}\n\nBuyurtma tafsilotlari:\n${orderInfo}\n\nRahmat!\n\nfile:///C:/Users/Saidkamol/Desktop/test/login.html`,
  };
  transporter.sendMail(mailOptions, (error, info) => {
    if (error) console.error("Email yuborishda xatolik:", error);
    else console.log("Email yuborildi:", info.response);
  });
};

// FOYDALANUVCHI CRUD (Create, Read, Update, Delete)

// CREATE (yangi foydalanuvchi)
app.post("/users", async (req, res) => {
  const { name, email, password, role, phone } = req.body;
  if (!name || !email || !password || !role) {
    return res.status(400).json({ message: "Barcha maydonlar kerak" });
  }
  const validRoles = ["user", "manager", "fixer"];
  if (!validRoles.includes(role)) {
    return res.status(400).json({ message: "Noto‘g‘ri rol turi" });
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  db.run(
    "INSERT INTO users (name, email, password, role, phone) VALUES (?, ?, ?, ?, ?)",
    [name, email, hashedPassword, role, phone || ""],
    function (err) {
      if (err)
        return res
          .status(500)
          .json({ message: "Qo‘shishda xatolik", error: err.message });
      res.json({ message: "Foydalanuvchi yaratildi", userId: this.lastID });
    }
  );
});

// Foydalanuvchi o‘zi buyurtma yaratadi
app.post(
  "/user/orders",
  authenticateToken,
  requireRole(["user"]),
  (req, res) => {
    const userId = req.user.id;
    const { description, serviceTime, customerType, name, district, phone } =
      req.body;

    if (
      !description ||
      !serviceTime ||
      !customerType ||
      !name ||
      !district ||
      !phone
    ) {
      return res
        .status(400)
        .json({ message: "Barcha maydonlar to‘ldirilishi shart" });
    }

    db.run(
      `INSERT INTO orders (userId, description, phone, serviceTime, customerType, name, district, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        userId,
        description,
        phone,
        serviceTime,
        customerType,
        name,
        district,
        "pending",
      ],
      function (err) {
        if (err)
          return res
            .status(500)
            .json({
              message: "Buyurtma yaratishda xatolik",
              error: err.message,
            });
        res
          .status(201)
          .json({
            message: "Buyurtma muvaffaqiyatli yaratildi",
            orderId: this.lastID,
          });
      }
    );
  }
);

// Foydalanuvchi o‘z buyurtmasini o‘chirish
app.delete(
  "/user/orders/:id",
  authenticateToken,
  requireRole(["user"]),
  (req, res) => {
    const userId = req.user.id;
    const orderId = req.params.id;

    // Buyurtma mavjudligi va userga tegishliligini tekshirish
    db.get(
      "SELECT * FROM orders WHERE id = ? AND userId = ?",
      [orderId, userId],
      (err, order) => {
        if (err)
          return res
            .status(500)
            .json({ message: "Server xatosi", error: err.message });
        if (!order)
          return res
            .status(404)
            .json({
              message: "Buyurtma topilmadi yoki bu sizga tegishli emas",
            });

        // Faqat pending statusdagi buyurtmani o‘chirishga ruxsat beramiz (ixtiyoriy)
        if (order.status !== "pending") {
          return res
            .status(400)
            .json({
              message: "Faqat 'pending' statusdagi buyurtmalar o‘chiriladi",
            });
        }

        db.run("DELETE FROM orders WHERE id = ?", [orderId], function (err) {
          if (err)
            return res
              .status(500)
              .json({
                message: "Buyurtmani o‘chirishda xatolik",
                error: err.message,
              });
          res.json({ message: "Buyurtma muvaffaqiyatli o‘chirildi", orderId });
        });
      }
    );
  }
);

// READ (barcha foydalanuvchilar)
app.get("/users", authenticateToken, (req, res) => {
  db.all(
    "SELECT id, name, email, role, phone FROM users ORDER BY id DESC",
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ message: "Olishda xatolik" });
      res.json(rows);
    }
  );
});

// READ (bitta foydalanuvchi)
app.get("/users/:id", authenticateToken, (req, res) => {
  db.get(
    "SELECT id, name, email, role, phone FROM users WHERE id = ?",
    [req.params.id],
    (err, user) => {
      if (err) return res.status(500).json({ message: "Olishda xatolik" });
      if (!user)
        return res.status(404).json({ message: "Foydalanuvchi topilmadi" });
      res.json(user);
    }
  );
});

// UPDATE (foydalanuvchini yangilash)
app.put("/users/:id", authenticateToken, async (req, res) => {
  const { name, email, password, role, phone } = req.body;
  const userId = req.params.id;

  let setPasswordSql = "";
  let params = [name, email, role, phone, userId];
  if (password) {
    const hashedPassword = await bcrypt.hash(password, 10);
    setPasswordSql = ", password = ?";
    params = [name, email, role, phone, hashedPassword, userId];
  }
  db.run(
    `UPDATE users SET name = ?, email = ?, role = ?, phone = ?${setPasswordSql} WHERE id = ?`,
    params,
    function (err) {
      if (err)
        return res
          .status(500)
          .json({ message: "Yangilashda xatolik", error: err.message });
      if (this.changes === 0)
        return res.status(404).json({ message: "Foydalanuvchi topilmadi" });
      res.json({ message: "Foydalanuvchi yangilandi" });
    }
  );
});

// DELETE (foydalanuvchini o‘chirish)
app.delete("/users/:id", authenticateToken, (req, res) => {
  db.run("DELETE FROM users WHERE id = ?", [req.params.id], function (err) {
    if (err)
      return res
        .status(500)
        .json({ message: "O‘chirishda xatolik", error: err.message });
    if (this.changes === 0)
      return res.status(404).json({ message: "Foydalanuvchi topilmadi" });
    res.json({ message: "Foydalanuvchi o‘chirildi" });
  });
});

// FOYDALANUVCHI LOGIN
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  console.log("Login attempt:", email, password);

  if (!email || !password)
    return res
      .status(400)
      .json({ message: "Email va parol kiritilishi kerak" });

  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
    if (err) {
      console.error("Database error:", err.message);
      return res.status(500).json({ message: "Server xatosi" });
    }

    if (!user) {
      console.log("User not found:", email);
      return res.status(401).json({ message: "Foydalanuvchi topilmadi" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    console.log("Password match:", isMatch);

    if (!isMatch) return res.status(401).json({ message: "Noto‘g‘ri parol" });

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: "24h" }
    );
    console.log("Generated Token:", token);
    res.json({ message: "Kirish muvaffaqiyatli", token, role: user.role });
  });
});

// User orderga javob beradi (tasdiqlaydi yoki rad etadi)
app.put("/user/orders/:id/userstatus", authenticateToken, (req, res) => {
  const userId = req.user.id;
  const orderId = req.params.id;
  const { userstatus } = req.body;
  console.log(userId); // "confirmed" yoki "canceled"

  if (!["confirmed", "canceled"].includes(userstatus)) {
    return res
      .status(400)
      .json({
        message: "Faqat 'confirmed' yoki 'canceled' qiymati bo'lishi mumkin",
      });
  }

  db.get(
    "SELECT * FROM orders WHERE id = ? AND userId = ?",
    [orderId, userId],
    (err, order) => {
      if (err) return res.status(500).json({ message: "Server xatosi" });
      if (!order)
        return res
          .status(404)
          .json({ message: "Buyurtma topilmadi yoki ruxsat yo‘q" });
      if (order.status !== "fixed" || order.userstatus !== "waiting")
        return res
          .status(400)
          .json({
            message:
              "Faqat statusi fixed va userstatus waiting bo‘lgan orderlar o‘zgartiriladi",
          });

      db.run(
        "UPDATE orders SET userstatus = ? WHERE id = ?",
        [userstatus, orderId],
        function (err) {
          if (err)
            return res
              .status(500)
              .json({ message: "Yangilashda xatolik", error: err.message });
          res.json({
            message: `Buyurtma userstatusi ${userstatus} ga o‘zgartirildi`,
          });
        }
      );
    }
  );
});

// FOYDALANUVCHI O‘Z PROFILINI KO‘RISH
app.get("/profile", authenticateToken, (req, res) => {
  const userId = req.user.id;
  db.get(
    "SELECT id, name, email, role, phone FROM users WHERE id = ?",
    [userId],
    (err, user) => {
      if (err) return res.status(500).json({ message: "Server xatosi" });
      if (!user)
        return res.status(404).json({ message: "Foydalanuvchi topilmadi" });
      res.json(user);
    }
  );
});

app.put("/profile", authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const { name, email, phone, password } = req.body;
  db.get("SELECT * FROM users WHERE id = ?", [userId], async (err, user) => {
    if (err) return res.status(500).json({ message: "Server xatosi" });
    if (!user)
      return res.status(404).json({ message: "Foydalanuvchi topilmadi" });

    const newName = name || user.name;
    const newEmail = email || user.email;
    const newPhone = phone || user.phone || "";

    // Parol yangilanishi kerakmi?
    if (password && password.trim().length >= 5) {
      const hashedPassword = await bcrypt.hash(password, 10);
      db.run(
        "UPDATE users SET name = ?, email = ?, phone = ?, password = ? WHERE id = ?",
        [newName, newEmail, newPhone, hashedPassword, userId],
        function (err) {
          if (err)
            return res
              .status(500)
              .json({ message: "Yangilashda xatolik", error: err.message });
          res.json({ message: "Profil va parol muvaffaqiyatli yangilandi" });
        }
      );
    } else {
      db.run(
        "UPDATE users SET name = ?, email = ?, phone = ? WHERE id = ?",
        [newName, newEmail, newPhone, userId],
        function (err) {
          if (err)
            return res
              .status(500)
              .json({ message: "Yangilashda xatolik", error: err.message });
          res.json({ message: "Profil muvaffaqiyatli yangilandi" });
        }
      );
    }
  });
});

// ORDERS (Buyurtmalar)

// Barcha buyurtmalar (status ko‘rsatiladi)
app.get("/orders", authenticateToken, (req, res) => {
  db.all(
    "SELECT *, createdAt as time FROM orders ORDER BY id DESC",
    [],
    (err, rows) => {
      if (err)
        return res
          .status(500)
          .json({ message: "Buyurtmalarni olishda xatolik" });
      res.json(rows);
    }
  );
});

// ... middleware va boshqa endpointlar

// Faqat manager uchun buyurtma yaratish endpointi
function requireManager(req, res, next) {
  if (req.user.role !== "manager") {
    return res
      .status(403)
      .json({ message: "Faqat manager buyurtma yaratishi mumkin" });
  }
  next();
}

app.post("/manager/orders", authenticateToken, requireManager, (req, res) => {
  const { description, name, phone } = req.body;
  if (!description || !name || !phone) {
    return res
      .status(400)
      .json({ message: "Barcha maydonlar kerak: description, name, phone" });
  }

  db.run(
    `INSERT INTO orders (userId, description, phone, name, status) VALUES (?, ?, ?, ?, ?)`,
    [0, description, phone, name, "pending"],
    function (err) {
      if (err)
        return res
          .status(500)
          .json({ message: "Buyurtma yaratishda xatolik", error: err.message });
      res
        .status(201)
        .json({
          message: "Buyurtma manager tomonidan yaratildi",
          orderId: this.lastID,
        });
    }
  );
});

// Faqat fixer role uchun
function requireFixer(req, res, next) {
  if (req.user.role !== "fixer") {
    return res.status(403).json({ message: "Faqat fixer ko‘rishi mumkin" });
  }
  next();
}

app.get("/fixer/orders", authenticateToken, requireFixer, (req, res) => {
  db.all(
    `SELECT id, userId, description, phone, serviceTime, customerType, name, district, status, createdAt as time
     FROM orders
     WHERE status = 'confirmed'
     ORDER BY id DESC`,
    [],
    (err, rows) => {
      if (err)
        return res
          .status(500)
          .json({ message: "Buyurtmalarni olishda xatolik" });
      res.json(rows);
    }
  );
});

app.get("/user/orders/fixed", authenticateToken, (req, res) => {
  const userId = req.user.id;
  db.all(
    `SELECT id, description, phone, serviceTime, customerType, name, district, status, cost, timeon, createdAt as time
     FROM orders
     WHERE userId = ? AND status = 'fixed'
     ORDER BY id DESC`,
    [userId],
    (err, rows) => {
      if (err)
        return res
          .status(500)
          .json({ message: "Buyurtmalarni olishda xatolik" });
      res.json(rows);
    }
  );
});

// Fixer orderga cost va timeon qo‘shadi
app.put("/fixer/orders/:id", authenticateToken, requireFixer, (req, res) => {
  const orderId = req.params.id;
  const { cost, timeon } = req.body;

  // Faqat confirmed orderlar uchun
  db.get("SELECT status FROM orders WHERE id = ?", [orderId], (err, row) => {
    if (err) return res.status(500).json({ message: "Buyurtma topilmadi" });
    if (!row) return res.status(404).json({ message: "Buyurtma mavjud emas" });
    if (row.status !== "confirmed")
      return res
        .status(400)
        .json({
          message: "Faqat confirmed bo'lgan buyurtmalarni yangilash mumkin",
        });

    db.run(
      `UPDATE orders SET cost = ?, timeon = ?, status = ? WHERE id = ?`,
      [cost, timeon, "fixed", orderId],
      function (err) {
        if (err)
          return res
            .status(500)
            .json({ message: "Yangilashda xatolik", error: err.message });
        if (this.changes === 0)
          return res.status(404).json({ message: "Buyurtma topilmadi" });
        res.json({
          message: "Buyurtma yangilandi va status 'fixed' ga o'zgardi",
          orderId,
        });
      }
    );
  });
});

// Yangi buyurtma qo'shish
app.post("/orders", async (req, res) => {
  const {
    customerType,
    name,
    district,
    serviceType,
    phone,
    email,
    description,
  } = req.body;
  if (
    !customerType ||
    !name ||
    !district ||
    !serviceType ||
    !phone ||
    !email ||
    !description
  ) {
    return res
      .status(400)
      .json({ message: "Barcha maydonlar to‘ldirilishi shart" });
  }
  db.get(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, existingUser) => {
      if (err) return res.status(500).json({ message: "Server xatosi" });

      let userId = null;
      let plainPassword = crypto.randomBytes(5).toString("hex");
      const hashedPassword = await bcrypt.hash(plainPassword, 10);

      if (!existingUser) {
        db.run(
          "INSERT INTO users (name, email, password, role, phone) VALUES (?, ?, ?, ?, ?)",
          [name, email, hashedPassword, "user", phone || ""],
          function (err) {
            if (err)
              return res
                .status(500)
                .json({ message: "Foydalanuvchini yaratishda xatolik" });
            userId = this.lastID;
            insertOrder(userId, plainPassword);
          }
        );
      } else {
        userId = existingUser.id;
        db.run(
          "UPDATE users SET name = ? WHERE id = ?",
          [name, userId],
          (err) => {
            if (err)
              return res
                .status(500)
                .json({ message: "Ismni yangilashda xatolik" });
            insertOrder(
              userId,
              "(Parolingiz o‘zgartirilmagan, eski parolingiz ishlaydi)"
            );
          }
        );
      }

      function insertOrder(uid, passwordToSend) {
        db.run(
          `INSERT INTO orders (userId, description, phone, serviceTime, customerType, name, district, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            uid,
            description,
            phone,
            serviceType,
            customerType,
            name,
            district,
            "pending",
          ],
          function (err) {
            if (err)
              return res
                .status(500)
                .json({ message: "Buyurtma yaratishda xatolik" });

            const orderText = `
Mijoz turi: ${customerType}
F.I.SH: ${name}
Tuman: ${district}
Xizmat turi: ${serviceType}
Telefon: ${phone}
Tavsif: ${description}
Buyurtma ID: ${this.lastID}
          `;
            sendOrderEmail(email, email, passwordToSend, orderText);
            res
              .status(201)
              .json({
                message: "Buyurtma muvaffaqiyatli qabul qilindi",
                orderId: this.lastID,
              });
          }
        );
      }
    }
  );
});

// Foydalanuvchining o‘z buyurtmalari
app.get("/user/orders", authenticateToken, (req, res) => {
  const userId = req.user.id;
  db.all(
    "SELECT *, createdAt AS time FROM orders WHERE userId = ? ORDER BY id DESC",
    [userId],
    (err, rows) => {
      if (err)
        return res
          .status(500)
          .json({ message: "Buyurtmalarni olishda xatolik" });
      res.json(rows);
    }
  );
});

// Status ustuni bor-yo‘qligini tekshirib, yo‘q bo‘lsa qo‘shadi:
db.get("PRAGMA table_info(orders);", [], (err, columns) => {
  if (err) {
    console.error("orders jadvali tekshirilmadi:", err.message);
  } else {
    // status ustuni bor-yo'qligini aniqlash
    db.all("PRAGMA table_info(orders);", [], (err, columns) => {
      if (err) {
        console.error("orders jadvali tekshirilmadi:", err.message);
      } else {
        const hasStatus = columns.some((col) => col.name === "status");
        if (!hasStatus) {
          db.run(
            "ALTER TABLE orders ADD COLUMN status TEXT DEFAULT 'pending';",
            [],
            (err) => {
              if (err)
                console.error(
                  "status ustunini qo'shishda xatolik:",
                  err.message
                );
              else console.log("status ustuni qo'shildi!");
            }
          );
        }
      }
    });
  }
});

// ORDER CONFIRM (Tasdiqlash) API
app.put(
  "/orders/:id/confirm",
  authenticateToken,
  requireRole(["manager", "fixer"]),
  (req, res) => {
    const orderId = req.params.id;
    db.run(
      "UPDATE orders SET status = ? WHERE id = ?",
      ["confirmed", orderId],
      function (err) {
        if (err)
          return res
            .status(500)
            .json({ message: "Tasdiqlashda xatolik", error: err.message });
        if (this.changes === 0)
          return res.status(404).json({ message: "Buyurtma topilmadi" });
        res.json({ message: "Buyurtma tasdiqlandi" });
      }
    );
  }
);

// Manager buyurtma o‘chirish
app.delete(
  "/manager/orders/:id",
  authenticateToken,
  requireRole(["manager"]),
  (req, res) => {
    const orderId = req.params.id;

    db.run("DELETE FROM orders WHERE id = ?", [orderId], function (err) {
      if (err) {
        return res
          .status(500)
          .json({
            message: "Buyurtmani o‘chirishda xatolik",
            error: err.message,
          });
      }
      if (this.changes === 0) {
        return res
          .status(404)
          .json({ message: "Buyurtma topilmadi yoki allaqachon o‘chirilgan" });
      }

      res.json({ message: "Buyurtma muvaffaqiyatli o‘chirildi", orderId });
    });
  }
);

// Statistics API Endpoint with Diagram Data
app.get(
  "/api/statistics",
  authenticateToken,
  requireRole(["manager", "fixer"]),
  (req, res) => {
    db.serialize(() => {
      db.get(
        "SELECT COUNT(*) AS totalOrders FROM orders",
        [],
        (err, totalOrdersRow) => {
          if (err)
            return res
              .status(500)
              .json({ message: "Xatolik", error: err.message });

          db.all(
            "SELECT status, COUNT(*) AS count FROM orders GROUP BY status",
            [],
            (err, statusRows) => {
              if (err)
                return res
                  .status(500)
                  .json({ message: "Xatolik", error: err.message });

              const statistics = {
                totalOrders: totalOrdersRow.totalOrders,
                byStatus: statusRows,
              };

              res.json(statistics);
            }
          );
        }
      );
    });
  }
);

// Statistics API Endpoint
app.get(
  "/statistics",
  authenticateToken,
  requireRole(["manager", "fixer"]),
  (req, res) => {
    db.serialize(() => {
      db.get(
        "SELECT COUNT(*) AS totalOrders FROM orders",
        [],
        (err, totalOrdersRow) => {
          if (err)
            return res
              .status(500)
              .json({ message: "Xatolik", error: err.message });

          db.get(
            'SELECT COUNT(*) AS confirmedOrders FROM orders WHERE status = "confirmed"',
            [],
            (err, confirmedOrdersRow) => {
              if (err)
                return res
                  .status(500)
                  .json({ message: "Xatolik", error: err.message });

              db.get(
                'SELECT COUNT(*) AS pendingOrders FROM orders WHERE status = "pending"',
                [],
                (err, pendingOrdersRow) => {
                  if (err)
                    return res
                      .status(500)
                      .json({ message: "Xatolik", error: err.message });

                  db.get(
                    'SELECT COUNT(*) AS fixedOrders FROM orders WHERE status = "fixed"',
                    [],
                    (err, fixedOrdersRow) => {
                      if (err)
                        return res
                          .status(500)
                          .json({ message: "Xatolik", error: err.message });

                      db.get(
                        'SELECT COUNT(*) AS canceledOrders FROM orders WHERE status = "canceled"',
                        [],
                        (err, canceledOrdersRow) => {
                          if (err)
                            return res
                              .status(500)
                              .json({ message: "Xatolik", error: err.message });

                          const statistics = {
                            totalOrders: totalOrdersRow.totalOrders,
                            confirmedOrders: confirmedOrdersRow.confirmedOrders,
                            pendingOrders: pendingOrdersRow.pendingOrders,
                            fixedOrders: fixedOrdersRow.fixedOrders,
                            canceledOrders: canceledOrdersRow.canceledOrders,
                          };

                          res.json(statistics);
                        }
                      );
                    }
                  );
                }
              );
            }
          );
        }
      );
    });
  }
);

// Serverni ishga tushurish
app.listen(PORT, () => {
  console.log(`✅ Server ${PORT}-portda ishlamoqda`);
});

// DB-ni yopish
process.on("SIGINT", () => {
  db.close((err) => {
    if (err) console.error("DB yopish xatosi:", err.message);
    console.log("SQLite ulanishi yopildi");
    process.exit(0);
  });
});
