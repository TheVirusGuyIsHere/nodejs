const express = require("express");
const axios = require("axios");
const multer = require("multer");
const FormData = require("form-data");
const crypto = require("crypto");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const sqlite3 = require("sqlite3").verbose();

const app = express();
app.use(express.json({limit:"25mb"}));
app.use(helmet());

/* ---------------- DATABASE ---------------- */

const db = new sqlite3.Database("./webhooks.db");

db.serialize(()=>{

db.run(`
CREATE TABLE IF NOT EXISTS webhooks (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 client_id TEXT UNIQUE,
 public_token TEXT UNIQUE,
 secret_key TEXT,
 discord_webhook TEXT,
 revoked INTEGER DEFAULT 0,
 created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
`);

});


/* ---------------- SECURITY ---------------- */

function rand(len=64){
 return crypto.randomBytes(len).toString("hex");
}

function signValid(req, secret){

 const sig=req.headers["x-signature"];
 if(!sig) return false;

 const body=JSON.stringify(req.body || {});
 const expected=crypto
  .createHmac("sha256",secret)
  .update(body)
  .digest("hex");

 return crypto.timingSafeEqual(
   Buffer.from(sig),
   Buffer.from(expected)
 );
}

/* -------- rate limiting per webhook -------- */

const limiter=rateLimit({
 windowMs:60*1000,
 max:30
});

app.use("/wh",limiter);



/* ------------- create protected webhook ------------- */

app.post("/api/create/discordwebhook",(req,res)=>{

 const {client_id,discord_webhook}=req.body;

 if(!client_id || !discord_webhook){
   return res.status(400).json({error:"missing"});
 }

 const publicToken=rand(24);
 const secretKey=rand(32);

 db.run(`
 INSERT INTO webhooks(
 client_id,
 public_token,
 secret_key,
 discord_webhook
 ) VALUES(?,?,?,?)
 `,
 [client_id,publicToken,secretKey,discord_webhook],
 function(err){

   if(err){
      return res.status(409).json({
       error:"exists"
      });
   }

   res.json({
    proxy_webhook:
      `${req.protocol}://${req.get("host")}/wh/${publicToken}`,
    signing_secret:secretKey
   });

 });

});


/* ---------- search existing ---------- */

app.get("/api/search/discordwebhook",(req,res)=>{

const client=req.query.client_id;

db.get(
"SELECT public_token FROM webhooks WHERE client_id=? AND revoked=0",
[client],
(err,row)=>{

 if(!row){
   return res.status(404).json({
     exists:false
   });
 }

 res.json({
   exists:true,
   webhook:
`${req.protocol}://${req.get("host")}/wh/${row.public_token}`
 });

});

});


/* ---------- rotate webhook ---------- */

app.post("/api/rotate/:client",(req,res)=>{

 const token=rand(24);

 db.run(
`UPDATE webhooks
SET public_token=?
WHERE client_id=?`,
[token,req.params.client],
()=>{

res.json({
 rotated:true,
 new_webhook:
`${req.protocol}://${req.get("host")}/wh/${token}`
});

});

});


/* ---------- revoke ---------- */

app.post("/api/revoke/:client",(req,res)=>{

db.run(
"UPDATE webhooks SET revoked=1 WHERE client_id=?",
[req.params.client],
()=>res.json({revoked:true})
);

});


/* ------------ multipart upload support ----------- */

const upload=multer({
 storage:multer.memoryStorage()
});


/*
Supports:
content
embeds
files
username
avatar_url
?wait=true
?thread_id=
*/
app.post(
"/wh/:token",
upload.any(),
async(req,res)=>{

db.get(
`SELECT * FROM webhooks
 WHERE public_token=?
 AND revoked=0`,
[req.params.token],

async(err,row)=>{

if(!row)
 return res.sendStatus(404);


/* HMAC auth */
if(!signValid(req,row.secret_key)){
 return res.status(403).json({
  error:"bad signature"
 });
}

try{

const params={};

if(req.query.wait)
 params.wait=req.query.wait;

if(req.query.thread_id)
 params.thread_id=req.query.thread_id;


/* multipart passthrough */
let response;

if(req.files?.length){

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

 response=await axios.post(
   row.discord_webhook,
   form,
   {
    params,
    headers:form.getHeaders()
   }
 );

}
else{

response=await axios.post(
 row.discord_webhook,
 req.body,
 {
   params,
   headers:{
    "Content-Type":"application/json"
   }
 });

}


/* pass Discord rate limit headers through */
[
"x-ratelimit-limit",
"x-ratelimit-remaining",
"x-ratelimit-reset"
].forEach(h=>{
 if(response.headers[h]){
   res.setHeader(
    h,
    response.headers[h]
   );
 }
});


return res
.status(response.status)
.send(response.data);


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

});

});

app.listen(3000,()=>{
 console.log("running");
});
