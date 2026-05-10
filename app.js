const express = require("express");
const path = require("path");
const crypto = require("crypto");
const axios = require("axios");
const multer = require("multer");
const FormData = require("form-data");
const sqlite3 = require("sqlite3").verbose();
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;

app.set("trust proxy", true);

app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, "public")));

if (!fs.existsSync("./data")) {
    fs.mkdirSync("./data");
}

const db = new sqlite3.Database("./data/webhooks.db", (err) => {
    if (err) {
        console.error("sqlite error:", err);
    } else {
        console.log("sqlite connected");
    }
});

db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS webhooks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE NOT NULL,
            discord_webhook TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_used DATETIME
        )
    `);
});

function generateToken() {
    return crypto.randomBytes(32).toString("hex");
}

function getWebhook(token) {
    return new Promise((resolve, reject) => {
        db.get(
            "SELECT * FROM webhooks WHERE token = ?",
            [token],
            (err, row) => {
                if (err) reject(err);
                else resolve(row);
            }
        );
    });
}

function updateLastUsed(token) {
    db.run(
        "UPDATE webhooks SET last_used = CURRENT_TIMESTAMP WHERE token = ?",
        [token]
    );
}

async function validateWebhook(url) {
    try {
        const r = await axios.get(url);

        return (
            r.status === 200 &&
            typeof r.data === "object" &&
            r.data.id
        );
    } catch {
        return false;
    }
}

function isDiscordWebhook(url) {
    return /^https:\/\/(canary\.|ptb\.)?discord\.com\/api\/webhooks\/\d+\/[\w-]+$/i.test(url);
}

app.post("/api/create/discordwebhook", async (req, res) => {
    try {
        let { discord_webhook } = req.body;

        if (!discord_webhook) {
            return res.status(400).json({
                error: "missing webhook"
            });
        }

        discord_webhook = discord_webhook.trim();

        if (!isDiscordWebhook(discord_webhook)) {
            return res.status(400).json({
                error: "invalid discord webhook"
            });
        }

        const valid = await validateWebhook(discord_webhook);

        if (!valid) {
            return res.status(400).json({
                error: "dead webhook"
            });
        }

        const token = generateToken();

        db.run(
            "INSERT INTO webhooks(token, discord_webhook) VALUES(?, ?)",
            [token, discord_webhook],
            (err) => {
                if (err) {
                    console.error(err);

                    return res.status(500).json({
                        error: "database error"
                    });
                }

                res.json({
                    success: true,
                    token,
                    proxy_webhook:
                        `${req.protocol}://${req.get("host")}/wh/${token}`
                });
            }
        );
    } catch (err) {
        console.error(err);

        res.status(500).json({
            error: "internal error"
        });
    }
});

app.get("/api/search/:token", async (req, res) => {
    try {
        const row = await getWebhook(req.params.token);

        if (!row) {
            return res.json({
                exists: false
            });
        }

        res.json({
            exists: true,
            created_at: row.created_at,
            last_used: row.last_used,
            proxy_webhook:
                `${req.protocol}://${req.get("host")}/wh/${row.token}`
        });
    } catch {
        res.status(500).json({
            error: "database error"
        });
    }
});

const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 25 * 1024 * 1024
    }
});

app.all("/wh/:token", upload.any(), async (req, res) => {
    try {
        const row = await getWebhook(req.params.token);

        if (!row) {
            return res.status(404).json({
                error: "proxy not found"
            });
        }

        updateLastUsed(req.params.token);

        let response;

        if (req.files && req.files.length > 0) {
            const form = new FormData();

            for (const key in req.body) {
                form.append(key, req.body[key]);
            }

            req.files.forEach((file, i) => {
                form.append(
                    `files[${i}]`,
                    file.buffer,
                    {
                        filename: file.originalname,
                        contentType: file.mimetype
                    }
                );
            });

            response = await axios.post(
                row.discord_webhook,
                form,
                {
                    headers: form.getHeaders(),
                    maxBodyLength: Infinity
                }
            );
        } else {
            response = await axios.post(
                row.discord_webhook,
                req.body,
                {
                    headers: {
                        "Content-Type": "application/json"
                    }
                }
            );
        }

        res.status(response.status).send(response.data);
    } catch (err) {
        console.error(err?.response?.data || err);

        if (err.response) {
            return res
                .status(err.response.status)
                .send(err.response.data);
        }

        res.status(500).json({
            error: "forward failed"
        });
    }
});

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.use((req, res) => {
    res.status(404).json({
        error: "not found"
    });
});

app.listen(PORT, () => {
    console.log(`running on ${PORT}`);
});
