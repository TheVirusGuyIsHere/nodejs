const express = require("express");
const path = require("path");
const crypto = require("crypto");
const axios = require("axios");
const multer = require("multer");
const FormData = require("form-data");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const sqlite3 = require("sqlite3").verbose();

const app = express();
const PORT = process.env.PORT || 3000;
const BASE_URL = "https://whp.mouz.dev";

app.set("trust proxy", 1);
app.use(helmet());

/* -------------------------
   STATIC WEBSITE (works again)
--------------------------*/
app.use(express.static(path.join(__dirname,"public")));

/* regular json for API routes */
app.use("/api", express.json({limit:"25mb"}));

/* -------------------------
   DATABASE
--------------------------*/
const db = new sqlite3.Database("./webhooks.db");

db.serialize(() => {

db.run(`
CREATE TABLE IF NOT EXISTS webhooks (
id INTEGER PRIMARY KEY AUTOINCREMENT,
public_token TEXT UNIQUE,
secret_key TEXT,
discord_webhook TEXT,
revoked INTEGER DEFAULT 0,
created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
`);

});

/* -------------------------
   HELPERS
--------------------------*/
function rand(bytes=32){
 return crypto.randomBytes(bytes).toString("hex");
}

function getWebhookByToken(token){
 return new Promise((resolve,reject)=>{
   db.get(
    "SELECT * FROM webhooks WHERE public_token=? AND revoked=0",
    [token],
    (e,row)=> e ? reject(e):resolve(row)
   );
 });
}

/* -------------------------
   RATE LIMIT
--------------------------*/
app.use("/wh",rateLimit({
 windowMs:60000,
 max:30
}));

/* -------------------------
   CREATE PROTECTED WEBHOOK
   no app ids anymore
--------------------------*/
app.post("/api/create/discordwebhook",(req,res)=>{

const {discord_webhook}=req.body;

if(!discord_webhook){
 return res.status(400).json({
   error:"discord_webhook required"
 });
}

const publicToken=rand(24);
const secretKey=rand(32);

db.run(`
INSERT INTO webhooks(
 public_token,
 secret_key,
 discord_webhook
) VALUES(?,?,?)
`,
[publicToken,secretKey,discord_webhook],
function(err){

 if(err){
   return res.status(500).json({
     error:"db insert failed"
   });
 }

res.json({
 proxy_webhook:`${BASE_URL}/wh/${publicToken}`,
 signing_secret:secretKey
});

});

});

/* -------------------------
   LOOKUP BY PROTECTED TOKEN
--------------------------*/
app.get("/api/search/discordwebhook/:token",(req,res)=>{

db.get(
"SELECT public_token,created_at FROM webhooks WHERE public_token=? AND revoked=0",
[req.params.token],
(err,row)=>{

 if(!row){
   return res.status(404).json({
    exists:false
   });
 }

 res.json({
   exists:true,
   webhook:`${BASE_URL}/wh/${row.public_token}`,
   created_at:row.created_at
 });

});

});


/* -------------------------
   ROTATE
--------------------------*/
app.post("/api/rotate/:token",(req,res)=>{

const newToken=rand(24);

db.run(
"UPDATE webhooks SET public_token=? WHERE public_token=?",
[newToken,req.params.token],
function(){

res.json({
 new_webhook:`${BASE_URL}/wh/${newToken}`
});

});

});


/* -------------------------
   REVOKE
--------------------------*/
app.post("/api/revoke/:token",(req,res)=>{

db.run(
"UPDATE webhooks SET revoked=1 WHERE public_token=?",
[req.params.token],
()=>res.json({revoked:true})
);

});


/* -------------------------
 RAW JSON WEBHOOK ROUTE
 exact body preserved for HMAC
--------------------------*/
app.post(
"/wh/:token",
express.raw({
 type:["application/json"],
 limit:"25mb"
}),
async(req,res)=>{

try{

const row=await getWebhookByToken(
 req.params.token
);

if(!row)
 return res.sendStatus(404);

const sig=req.headers["x-signature"];

const expected=crypto
.createHmac(
 "sha256",
 row.secret_key
)
.update(req.body)
.digest("hex");

if(sig!==expected){
 return res.status(403).json({
  error:"bad signature"
 });
}

const params={};

if(req.query.wait)
 params.wait=req.query.wait;

if(req.query.thread_id)
 params.thread_id=req.query.thread_id;

const jsonBody=JSON.parse(
 req.body.toString()
);

const r=await axios.post(
 row.discord_webhook,
 jsonBody,
 {
   params
 }
);

res
.status(r.status)
.send(r.data);

}catch(e){

if(e.response){
 return res
 .status(e.response.status)
 .send(e.response.data);
}

res.status(500).json({
 error:"relay failed"
});

}

}
);

/* -------------------------
 MULTIPART FILE WEBHOOK
--------------------------*/
const upload=multer({
 storage:multer.memoryStorage()
});

app.post(
"/wh/:token/files",
upload.any(),
async(req,res)=>{

try{

const row=await getWebhookByToken(
 req.params.token
);

if(!row)
 return res.sendStatus(404);

const form=new FormData();

Object.keys(req.body).forEach(k=>{
 form.append(k,req.body[k]);
});

req.files.forEach((f,i)=>{
 form.append(
  `files[${i}]`,
  f.buffer,
  f.originalname
 );
});

const r=await axios.post(
 row.discord_webhook,
 form,
 {
  headers:form.getHeaders()
 }
);

res
.status(r.status)
.send(r.data);

}catch(e){
res.status(500).json({
 error:"upload relay failed"
});
}

});


/* -------------------------
 homepage fallback
--------------------------*/
app.get("/",(req,res)=>{
res.sendFile(
 path.join(__dirname,"public","index.html")
);
});


/* 404 */
app.use((req,res)=>{
res.status(404).sendFile(
path.join(__dirname,"public","404.html")
);
});

app.listen(PORT,()=>{
 console.log(
  "running on "+PORT
 );
});
