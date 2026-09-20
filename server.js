import "dotenv/config";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import express from "express";
import cors from "cors";
import admin from "firebase-admin";

const __filename=fileURLToPath(import.meta.url);
const __dirname=path.dirname(__filename);
const app=express();
const PORT=Number(process.env.PORT||8080);
const SUPER_ADMIN_EMAIL=String(process.env.SUPER_ADMIN_EMAIL||"tranducmanh2109@gmail.com").trim().toLowerCase();
const allowedOrigins=String(process.env.ALLOWED_ORIGINS||"").split(",").map(v=>v.trim()).filter(Boolean);

function initAdmin(){
  if(admin.apps.length)return admin.app();
  if(process.env.FIREBASE_SERVICE_ACCOUNT_JSON){
    return admin.initializeApp({credential:admin.credential.cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON))});
  }
  const projectId=String(process.env.FIREBASE_PROJECT_ID||"").trim();
  const clientEmail=String(process.env.FIREBASE_CLIENT_EMAIL||"").trim();
  const privateKey=String(process.env.FIREBASE_PRIVATE_KEY||"").replace(/\\n/g,"\n");
  if(projectId&&clientEmail&&privateKey){
    return admin.initializeApp({credential:admin.credential.cert({projectId,clientEmail,privateKey})});
  }
  return admin.initializeApp({credential:admin.credential.applicationDefault()});
}

let firebaseReady=false;
try{initAdmin();firebaseReady=true;}catch(error){console.error("[Firebase Admin] Không khởi tạo được:",error.message);}

const db=()=>admin.firestore();
const auth=()=>admin.auth();
const SERVER_TIMESTAMP=()=>admin.firestore.FieldValue.serverTimestamp();
const ALLOWED_CONTENT_COLLECTIONS=new Set(["popups","polls","quizzes","homework","attendance","confessions","privateFeedback","quizResults"]);
const DEFAULT_STUDENT_EMAIL_DOMAIN="a8thcscl2.firebaseapp.com";
const STUDENT_EMAIL_DOMAIN=String(process.env.STUDENT_EMAIL_DOMAIN||DEFAULT_STUDENT_EMAIL_DOMAIN).trim().toLowerCase();

app.disable("x-powered-by");
app.set("trust proxy",1);
app.use(cors({
  origin(origin,callback){
    if(!origin||!allowedOrigins.length||allowedOrigins.includes("*"))return callback(null,true);
    return callback(null,allowedOrigins.includes(origin));
  },
  credentials:true
}));
app.use(express.json({limit:"2mb"}));
app.use(express.static(__dirname,{extensions:["html"]}));

function safeId(value){return String(value??"").trim();}
function cleanName(value){return String(value??"").trim().replace(/\s+/g," ");}
function cleanEmail(value){return String(value??"").trim().toLowerCase();}
function slugify(value){return cleanName(value).normalize("NFD").replace(/[\u0300-\u036f]/g,"").toLowerCase().replace(/[^a-z0-9]+/g,"-").replace(/(^-|-$)/g,"").slice(0,35)||"thanh-vien";}
function validEmail(value){return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail(value));}
function randomPassword(){return `A8a8!${crypto.randomBytes(8).toString("base64url")}`.slice(0,16);}
function generatedEmail(name){return `a8a8.${slugify(name)}.${crypto.randomBytes(4).toString("hex")}@${STUDENT_EMAIL_DOMAIN}`;}
function sendError(res,status,message,error){return res.status(status).json({message,detail:error?.message||undefined});}

async function authenticated(req,res,next){
  if(!firebaseReady)return res.status(503).json({message:"Firebase Admin SDK chưa được cấu hình trên backend."});
  try{
    const header=req.get("Authorization")||"";
    if(!header.startsWith("Bearer "))return res.status(401).json({message:"Thiếu Firebase ID token."});
    req.user=await auth().verifyIdToken(header.slice(7),true);
    next();
  }catch(error){return sendError(res,401,"Firebase ID token không hợp lệ.",error);}
}

async function adminOnly(req,res,next){
  try{
    const snap=await db().collection("users").doc(req.user.uid).get();
    const profile=snap.exists?snap.data():{};
    if(!["admin","super_admin"].includes(profile.role))return res.status(403).json({message:"Bạn không có quyền quản trị."});
    req.profile={uid:req.user.uid,email:req.user.email||"",...profile};
    next();
  }catch(error){return sendError(res,500,"Không thể đọc quyền quản trị.",error);}
}

async function superOnly(req,res,next){
  if(req.profile?.role!=="super_admin"&&cleanEmail(req.user.email)!==SUPER_ADMIN_EMAIL){
    return res.status(403).json({message:"Chỉ Super Admin mới được phép thực hiện thao tác này."});
  }
  next();
}

function popupStyle(input){
  const size=["small","normal","large"].includes(String(input?.size||"normal"))?String(input.size):"normal";
  const radius=Math.min(48,Math.max(18,Number(input?.radius||30)));
  const accent=/^#[0-9a-fA-F]{6}$/.test(String(input?.accentColor||""))?String(input.accentColor):"#14b8a6";
  const imageUrl=String(input?.imageUrl||"").trim();
  const buttonLabel=String(input?.buttonLabel||"Tôi đã đọc & hiểu rõ").trim().slice(0,60)||"Tôi đã đọc & hiểu rõ";
  return {size,radius,accentColor:accent,imageUrl,buttonLabel};
}

async function createStudentAccount(input,createdBy){
  const name=cleanName(input?.name);
  if(!name)throw new Error("Họ và tên là bắt buộc.");
  const email=cleanEmail(input?.email)||generatedEmail(name);
  if(!validEmail(email))throw new Error("Email đăng nhập không hợp lệ.");
  const password=String(input?.password||"").trim()||randomPassword();
  if(password.length<6)throw new Error("Mật khẩu phải có ít nhất 6 ký tự.");

  let account=null;
  try{
    account=await auth().createUser({email,password,displayName:name});
    const uid=account.uid;
    const dob=String(input?.dob||"");
    const gender=String(input?.gender||"");
    const team=String(input?.team||"");
    const classRole=String(input?.classRole||"Học sinh");
    const batch=db().batch();
    batch.set(db().collection("users").doc(uid),{
      uid,email,displayName:name,role:"student",classRole,team,studentId:uid,studentUid:uid,
      bio:"",photoURL:"",themeColors:null,createdAt:SERVER_TIMESTAMP(),updatedAt:SERVER_TIMESTAMP(),createdBy:createdBy||null
    });
    batch.set(db().collection("students").doc(uid),{
      id:uid,uid,name,dob,gender,team,classRole,score:10,badges:[],history:[],accountUid:uid,accountEmail:email,
      createdAt:SERVER_TIMESTAMP(),updatedAt:SERVER_TIMESTAMP(),createdBy:createdBy||null
    });
    await batch.commit();
    return {id:uid,uid,name,dob,gender,team,classRole,email,temporaryPassword:password,passwordProvided:Boolean(input?.password),accountUid:uid};
  }catch(error){
    if(account?.uid){try{await auth().deleteUser(account.uid);}catch(rollbackError){console.error("[Rollback Auth]",rollbackError.message);}}
    if(error?.code==="auth/email-already-exists")throw new Error(`Email ${email} đã tồn tại trong Firebase Authentication.`);
    throw error;
  }
}

app.get("/api/health",(req,res)=>res.json({ok:true,service:"8A8 Class Portal Backend",timestamp:new Date().toISOString(),timezone:"Asia/Ho_Chi_Minh",firebaseReady,studentEmailDomain:STUDENT_EMAIL_DOMAIN}));
app.get("/api/runtime-config",(req,res)=>res.json({superAdminEmail:SUPER_ADMIN_EMAIL,studentEmailDomain:STUDENT_EMAIL_DOMAIN}));

app.post("/api/admin/students/create",authenticated,adminOnly,async(req,res)=>{
  try{
    const student=await createStudentAccount(req.body,req.user.uid);
    return res.status(201).json({ok:true,student});
  }catch(error){return sendError(res,400,"Không thể tạo tài khoản học sinh.",error);}
});

app.post("/api/admin/students/create-bulk",authenticated,adminOnly,async(req,res)=>{
  const rows=Array.isArray(req.body?.students)?req.body.students:[];
  if(!rows.length)return res.status(400).json({message:"Danh sách thành viên trống."});
  if(rows.length>100)return res.status(400).json({message:"Mỗi lần chỉ được tạo tối đa 100 tài khoản."});
  const created=[];const failed=[];
  for(let index=0;index<rows.length;index++){
    try{created.push(await createStudentAccount(rows[index],req.user.uid));}
    catch(error){failed.push({row:index+1,name:cleanName(rows[index]?.name),email:cleanEmail(rows[index]?.email),message:error?.message||"Lỗi không xác định."});}
  }
  return res.status(200).json({ok:failed.length===0,created,failed,total:rows.length});
});

app.patch("/api/admin/students/:id/score",authenticated,adminOnly,async(req,res)=>{
  try{
    const id=safeId(req.params.id);const points=Number(req.body?.points);const reason=String(req.body?.reason||"").trim();
    if(!id||!Number.isFinite(points)||![-1,1].includes(points)||!reason)return res.status(400).json({message:"Dữ liệu cộng/trừ điểm không hợp lệ."});
    const ref=db().collection("students").doc(id);
    await db().runTransaction(async tx=>{
      const snap=await tx.get(ref);
      if(!snap.exists)throw new Error("Không tìm thấy học sinh.");
      const old=snap.data();
      const score=Math.max(0,Number(old.score??10)+points);
      const history=Array.isArray(old.history)?old.history:[];
      tx.update(ref,{score,history:[...history,{type:points>0?"praise":"criticism",points,reason,timestamp:new Date().toISOString(),by:req.user.uid}],updatedAt:SERVER_TIMESTAMP()});
    });
    res.json({ok:true});
  }catch(error){return sendError(res,500,"Không thể cập nhật điểm thi đua.",error);}
});

app.post("/api/admin/students/:id/reset-password",authenticated,adminOnly,async(req,res)=>{
  try{
    const id=safeId(req.params.id);if(!id)return res.status(400).json({message:"Thiếu student id."});
    const snap=await db().collection("students").doc(id).get();
    if(!snap.exists)return res.status(404).json({message:"Không tìm thấy học sinh."});
    const student=snap.data();const uid=safeId(student.accountUid||student.studentUid||student.uid||id);
    if(!uid)return res.status(404).json({message:"Học sinh này chưa liên kết tài khoản Firebase."});
    const target=await auth().getUser(uid);
    if(cleanEmail(target.email)===SUPER_ADMIN_EMAIL)return res.status(403).json({message:"Không được đổi mật khẩu tài khoản Super Admin chính từ đây."});
    const password=String(req.body?.password||"").trim()||randomPassword();
    if(password.length<6)return res.status(400).json({message:"Mật khẩu phải có ít nhất 6 ký tự."});
    await auth().updateUser(uid,{password});
    await db().collection("users").doc(uid).set({updatedAt:SERVER_TIMESTAMP(),passwordResetAt:SERVER_TIMESTAMP(),passwordResetBy:req.user.uid},{merge:true});
    return res.json({ok:true,email:target.email,temporaryPassword:password,uid});
  }catch(error){return sendError(res,400,"Không thể cấp lại mật khẩu.",error);}
});

app.delete("/api/admin/students/:id",authenticated,adminOnly,async(req,res)=>{
  try{
    const id=safeId(req.params.id);if(!id)return res.status(400).json({message:"Thiếu student id."});
    const studentRef=db().collection("students").doc(id);const snap=await studentRef.get();
    if(!snap.exists)return res.status(404).json({message:"Không tìm thấy học sinh."});
    const student=snap.data();const uid=safeId(student.accountUid||student.studentUid||student.uid||id);
    if(uid){
      try{
        const target=await auth().getUser(uid);
        if(cleanEmail(target.email)===SUPER_ADMIN_EMAIL)return res.status(403).json({message:"Không được xóa tài khoản Super Admin."});
        await auth().deleteUser(uid);
      }catch(error){if(error.code!=="auth/user-not-found")throw error;}
    }
    const batch=db().batch();batch.delete(studentRef);if(uid)batch.delete(db().collection("users").doc(uid));await batch.commit();
    res.json({ok:true});
  }catch(error){return sendError(res,500,"Không thể xóa học sinh và tài khoản liên kết.",error);}
});

app.post("/api/admin/popup",authenticated,adminOnly,async(req,res)=>{
  try{
    const title=String(req.body?.title||"").trim();const content=String(req.body?.content||"").trim();
    if(!title||!content)return res.status(400).json({message:"Tiêu đề và nội dung Popup là bắt buộc."});
    const style=popupStyle(req.body);
    const ref=await db().collection("popups").add({title,content,active:req.body?.active!==false,...style,createdBy:req.user.uid,createdAt:SERVER_TIMESTAMP(),updatedAt:SERVER_TIMESTAMP(),dailyResetNonce:Date.now()});
    res.status(201).json({ok:true,id:ref.id});
  }catch(error){return sendError(res,400,"Không thể tạo Popup.",error);}
});

app.post("/api/admin/popup/reset",authenticated,adminOnly,async(req,res)=>{
  try{
    const snap=await db().collection("popups").where("active","==",true).get();
    const batch=db().batch();snap.docs.forEach(docSnap=>batch.update(docSnap.ref,{dailyResetNonce:Date.now(),dailyResetAt:SERVER_TIMESTAMP(),updatedAt:SERVER_TIMESTAMP()}));
    if(snap.size)await batch.commit();
    res.json({ok:true,count:snap.size});
  }catch(error){return sendError(res,500,"Không thể reset trạng thái đọc Popup.",error);}
});

app.post("/api/admin/content/:collection",authenticated,adminOnly,async(req,res)=>{
  try{
    const collection=safeId(req.params.collection);
    if(!ALLOWED_CONTENT_COLLECTIONS.has(collection))return res.status(400).json({message:"Collection không được phép."});
    const payload={...(req.body||{}),createdBy:req.user.uid,createdAt:SERVER_TIMESTAMP(),updatedAt:SERVER_TIMESTAMP()};
    const ref=await db().collection(collection).add(payload);
    res.status(201).json({ok:true,id:ref.id});
  }catch(error){return sendError(res,500,`Không thể tạo dữ liệu trong ${req.params.collection}.`,error);}
});

app.patch("/api/admin/content/:collection/:id",authenticated,adminOnly,async(req,res)=>{
  try{
    const collection=safeId(req.params.collection),id=safeId(req.params.id);
    if(!ALLOWED_CONTENT_COLLECTIONS.has(collection))return res.status(400).json({message:"Collection không được phép."});
    if(!id)return res.status(400).json({message:"Thiếu id."});
    const patch={...(req.body||{}),updatedAt:SERVER_TIMESTAMP()};
    delete patch.createdAt;delete patch.createdBy;
    await db().collection(collection).doc(id).update(patch);
    res.json({ok:true});
  }catch(error){return sendError(res,500,"Không thể cập nhật dữ liệu.",error);}
});

app.delete("/api/admin/content/:collection/:id",authenticated,adminOnly,async(req,res)=>{
  try{
    const collection=safeId(req.params.collection),id=safeId(req.params.id);
    if(!ALLOWED_CONTENT_COLLECTIONS.has(collection))return res.status(400).json({message:"Collection không được phép."});
    if(!id)return res.status(400).json({message:"Thiếu id."});
    await db().collection(collection).doc(id).delete();
    res.json({ok:true});
  }catch(error){return sendError(res,500,"Không thể xóa dữ liệu.",error);}
});

app.patch("/api/super-admin/users/:uid/role",authenticated,adminOnly,superOnly,async(req,res)=>{
  try{
    const uid=safeId(req.params.uid),role=safeId(req.body?.role);
    if(!uid||!["student","admin"].includes(role))return res.status(400).json({message:"uid hoặc role không hợp lệ."});
    const target=await auth().getUser(uid);
    if(cleanEmail(target.email)===SUPER_ADMIN_EMAIL)return res.status(403).json({message:"Không được hạ quyền Super Admin chính."});
    await db().collection("users").doc(uid).set({role,updatedAt:SERVER_TIMESTAMP(),updatedBy:req.user.uid},{merge:true});
    res.json({ok:true,uid,role});
  }catch(error){return sendError(res,500,"Không thể đổi role.",error);}
});

app.get("/manifest.webmanifest",(req,res)=>res.type("application/manifest+json").send(JSON.stringify({
  name:"Portal 8A8 - Trường THCS Cẩm Lý 2",short_name:"Portal 8A8",start_url:"/index.html#trang-chu",scope:"/",display:"standalone",
  background_color:"#f1f5f9",theme_color:"#14b8a6",description:"Cổng thông tin lớp 8A8 - Trường THCS Cẩm Lý 2.",
  icons:[{src:"/logo.png",sizes:"500x500",type:"image/png",purpose:"any maskable"}]
})));
app.get("/admin.html",(req,res)=>res.sendFile(path.join(__dirname,"admin.html")));
app.get("/admin",(req,res)=>res.sendFile(path.join(__dirname,"admin.html")));
app.get("/",(req,res)=>res.sendFile(path.join(__dirname,"index.html")));

app.listen(PORT,()=>console.log(`Portal 8A8 backend listening on ${PORT}`));
