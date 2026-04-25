const express = require("express");
const path = require("path");
const crypto = require("crypto");
const axios = require("axios");
const multer = require("multer");
const FormData = require("form-data");
const sqlite3 = require("sqlite3").verbose();

const app = express();
const PORT = process.env.PORT || 3000;

app.set("trust proxy", 1);

app.use(express.json({ limit: "25mb" }));
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, "public")));

const db = new sqlite3.Database("./webhooks.db");

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS webhooks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token TEXT UNIQUE,
      discord_webhook TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
});

function token() {
  return crypto.randomBytes(32).toString("hex");
}

function get(token) {
  return new Promise((resolve, reject) => {
    db.get(
      "SELECT * FROM webhooks WHERE token=?",
      [token],
      (e, r) => (e ? reject(e) : resolve(r))
    );
  });
}

app.post("/api/create/discordwebhook", (req, res) => {
  const { discord_webhook } = req.body;
  if (!discord_webhook) return res.status(400).json({ error: "missing" });

  const t = token();

  db.run(
    "INSERT INTO webhooks(token,discord_webhook) VALUES(?,?)",
    [t, discord_webhook],
    (e) => {
      if (e) return res.status(500).json({ error: "db error" });

      res.json({
        proxy_webhook: `${req.protocol}://${req.get("host")}/wh/${t}`
      });
    }
  );
});

app.get("/api/search/:token", (req, res) => {
  db.get(
    "SELECT token FROM webhooks WHERE token=?",
    [req.params.token],
    (e, r) => {
      if (!r) return res.json({ exists: false });
      res.json({
        exists: true,
        webhook: `${req.protocol}://${req.get("host")}/wh/${r.token}`
      });
    }
  );
});

app.post("/wh/:token", async (req, res) => {
  const row = await get(req.params.token);
  if (!row) return res.sendStatus(404);

  try {
    const r = await axios.post(row.discord_webhook, req.body, {
      headers: { "Content-Type": "application/json" }
    });

    res.status(r.status).send(r.data);
  } catch (e) {
    if (e.response) return res.status(e.response.status).send(e.response.data);
    res.status(500).json({ error: "failed" });
  }
});

const upload = multer({ storage: multer.memoryStorage() });

app.post("/wh/:token/files", upload.any(), async (req, res) => {
  const row = await get(req.params.token);
  if (!row) return res.sendStatus(404);

  const form = new FormData();

  Object.keys(req.body).forEach(k => form.append(k, req.body[k]));

  req.files.forEach((f, i) => {
    form.append(`files[${i}]`, f.buffer, f.originalname);
  });

  try {
    const r = await axios.post(row.discord_webhook, form, {
      headers: form.getHeaders()
    });

    res.status(r.status).send(r.data);
  } catch {
    res.status(500).json({ error: "upload failed" });
  }
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, "public", "404.html"));
});

app.listen(PORT, () => {
  console.log("running " + PORT);
});
