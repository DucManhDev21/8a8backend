import "dotenv/config";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import express from "express";
import cors from "cors";
import admin from "firebase-admin";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();

const PORT = Number(process.env.PORT || 8080);
const SUPER_ADMIN_EMAIL = String(
  process.env.SUPER_ADMIN_EMAIL || "tranducmanh2109@gmail.com"
).trim().toLowerCase();
const DEFAULT_STUDENT_EMAIL_DOMAIN = "a8thcscl2.firebaseapp.com";
const STUDENT_EMAIL_DOMAIN = String(
  process.env.STUDENT_EMAIL_DOMAIN || DEFAULT_STUDENT_EMAIL_DOMAIN
).trim().toLowerCase();
const allowedOrigins = String(process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((value) => value.trim())
  .filter(Boolean);

const ADMIN_ROLES = new Set(["admin", "super_admin"]);
const USER_ROLES = new Set(["student", "admin", "super_admin"]);
const CONTENT_COLLECTIONS = new Set([
  "popups",
  "polls",
  "quizzes",
  "homework",
  "attendance",
  "confessions",
  "privateFeedback",
  "quizResults",
  "honors",
  "notifications",
]);

app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes("*")) {
        return callback(null, true);
      }
      return callback(null, allowedOrigins.includes(origin));
    },
    credentials: true,
  })
);
app.use(express.json({ limit: "3mb" }));
app.use(express.static(__dirname, { extensions: ["html"] }));

function initFirebaseAdmin() {
  if (admin.apps.length) return admin.app();

  if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
    return admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
    });
  }

  const projectId = String(process.env.FIREBASE_PROJECT_ID || "").trim();
  const clientEmail = String(process.env.FIREBASE_CLIENT_EMAIL || "").trim();
  const privateKey = String(process.env.FIREBASE_PRIVATE_KEY || "").replace(
    /\\n/g,
    "\n"
  );

  if (projectId && clientEmail && privateKey) {
    return admin.initializeApp({
      credential: admin.credential.cert({
        projectId,
        clientEmail,
        privateKey,
      }),
    });
  }

  return admin.initializeApp({
    credential: admin.credential.applicationDefault(),
  });
}

let firebaseReady = false;
try {
  initFirebaseAdmin();
  firebaseReady = true;
} catch (error) {
  console.error("[Firebase Admin] Không khởi tạo được:", error?.message || error);
}

const db = () => admin.firestore();
const auth = () => admin.auth();
const SERVER_TIMESTAMP = () => admin.firestore.FieldValue.serverTimestamp();

function safeId(value) {
  return String(value ?? "").trim();
}

function cleanName(value) {
  return String(value ?? "").trim().replace(/\s+/g, " ");
}

function cleanEmail(value) {
  return String(value ?? "").trim().toLowerCase();
}

function normalizeUsername(value) {
  return String(value ?? "")
    .trim()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "")
    .replace(/^[-_.]+|[-_.]+$/g, "")
    .slice(0, 32);
}

function slugify(value) {
  return cleanName(value)
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "")
    .slice(0, 32) || "thanh-vien";
}

function validEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail(value));
}

function randomPassword() {
  return `A8a8!${crypto.randomBytes(8).toString("base64url")}`.slice(0, 16);
}

function sendError(res, status, message, error) {
  return res.status(status).json({
    ok: false,
    message,
    detail: error?.message || undefined,
    code: error?.code || undefined,
  });
}

function isHardcodedSuperAdmin(decodedUser) {
  return cleanEmail(decodedUser?.email) === SUPER_ADMIN_EMAIL;
}

function getClaimRole(decodedUser) {
  const claimRole = safeId(decodedUser?.role || decodedUser?.adminRole);
  return USER_ROLES.has(claimRole) ? claimRole : "";
}

async function ensureSuperAdminProfile(decodedUser) {
  if (!decodedUser?.uid) throw new Error("Token không có uid.");

  const uid = decodedUser.uid;
  const email = cleanEmail(decodedUser.email);
  const ref = db().collection("users").doc(uid);
  const snap = await ref.get();
  const current = snap.exists ? snap.data() : {};

  const profile = {
    uid,
    email,
    displayName:
      cleanName(current.displayName) || cleanName(decodedUser.name) || "Super Admin",
    role: "super_admin",
    classRole: current.classRole || "Quản trị hệ thống",
    team: current.team || "",
    bio: current.bio || "",
    photoURL: current.photoURL || "",
    themeColors: current.themeColors || null,
    updatedAt: SERVER_TIMESTAMP(),
  };

  if (!snap.exists) {
    profile.createdAt = SERVER_TIMESTAMP();
  }

  await ref.set(profile, { merge: true });

  try {
    await auth().setCustomUserClaims(uid, { role: "super_admin", admin: true });
  } catch (claimsError) {
    console.warn("[Claims] Không thể set super_admin claims:", claimsError?.message);
  }

  return { ...profile, role: "super_admin" };
}

/**
 * Xác định quyền quản trị theo thứ tự:
 * 1. Email Super Admin cố định.
 * 2. Firebase Custom Claims.
 * 3. Firestore users/{uid}.
 *
 * Hàm này được dùng chung cho /api/admin/verify và adminOnly để frontend
 * và backend luôn sử dụng cùng một logic quyền.
 */
async function resolveAdminProfile(decodedUser) {
  if (!decodedUser?.uid) throw new Error("Token Firebase không có uid.");

  if (isHardcodedSuperAdmin(decodedUser)) {
    return {
      allowed: true,
      role: "super_admin",
      source: "hardcoded-email",
      profile: await ensureSuperAdminProfile(decodedUser),
    };
  }

  const claimRole = getClaimRole(decodedUser);
  if (ADMIN_ROLES.has(claimRole) || decodedUser?.admin === true) {
    const role = claimRole === "super_admin" ? "super_admin" : "admin";
    await db().collection("users").doc(decodedUser.uid).set(
      {
        uid: decodedUser.uid,
        email: cleanEmail(decodedUser.email),
        displayName: cleanName(decodedUser.name) || cleanEmail(decodedUser.email),
        role,
        updatedAt: SERVER_TIMESTAMP(),
      },
      { merge: true }
    );
    return {
      allowed: true,
      role,
      source: "custom-claims",
      profile: {
        uid: decodedUser.uid,
        email: cleanEmail(decodedUser.email),
        displayName: cleanName(decodedUser.name) || cleanEmail(decodedUser.email),
        role,
      },
    };
  }

  const snap = await db().collection("users").doc(decodedUser.uid).get();
  const profile = snap.exists ? snap.data() : {};
  if (!ADMIN_ROLES.has(profile.role)) {
    return {
      allowed: false,
      role: profile.role || "student",
      source: "firestore",
      profile: {
        uid: decodedUser.uid,
        email: cleanEmail(decodedUser.email),
        ...profile,
      },
    };
  }

  try {
    await auth().setCustomUserClaims(decodedUser.uid, {
      role: profile.role,
      admin: profile.role === "admin" || profile.role === "super_admin",
    });
  } catch (claimsError) {
    console.warn("[Claims] Không thể đồng bộ claims từ Firestore role:", claimsError?.message);
  }

  return {
    allowed: true,
    role: profile.role,
    source: "firestore",
    profile: {
      uid: decodedUser.uid,
      email: cleanEmail(decodedUser.email),
      ...profile,
    },
  };
}

/**
 * Xác thực Firebase ID token. Không đọc Firestore ở middleware này vì token
 * phải được kiểm tra trước khi phân quyền.
 */
async function authenticated(req, res, next) {
  if (!firebaseReady) {
    return res.status(503).json({
      ok: false,
      message: "Firebase Admin SDK chưa được cấu hình trên backend.",
    });
  }

  try {
    const header = req.get("Authorization") || "";
    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({ ok: false, message: "Thiếu Firebase ID token." });
    }

    const token = header.slice(7).trim();
    if (!token) {
      return res.status(401).json({ ok: false, message: "Firebase ID token rỗng." });
    }

    req.user = await auth().verifyIdToken(token, true);
    return next();
  } catch (error) {
    return sendError(res, 401, "Firebase ID token không hợp lệ hoặc đã hết hạn.", error);
  }
}

/**
 * Middleware phân quyền backend dùng đúng resolver đa tầng với endpoint verify.
 */
async function adminOnly(req, res, next) {
  try {
    const result = await resolveAdminProfile(req.user);
    if (!result.allowed) {
      return res.status(403).json({
        ok: false,
        message: "Tài khoản này không có quyền quản trị.",
        role: result.role,
        source: result.source,
      });
    }
    req.profile = result.profile;
    req.adminVerification = result;
    return next();
  } catch (error) {
    return sendError(res, 500, "Không thể xác minh quyền quản trị.", error);
  }
}

async function superOnly(req, res, next) {
  const isSuper =
    req.profile?.role === "super_admin" || isHardcodedSuperAdmin(req.user);
  if (!isSuper) {
    return res.status(403).json({
      ok: false,
      message: "Chỉ Super Admin mới được phép thực hiện thao tác này.",
    });
  }
  return next();
}

function sanitizePopupStyle(input) {
  const size = ["small", "normal", "large", "wide"].includes(
    String(input?.size || "normal")
  )
    ? String(input.size)
    : "normal";

  const radius = Math.min(48, Math.max(12, Number(input?.radius || 30)));
  const accentColor = /^#[0-9a-fA-F]{6}$/.test(String(input?.accentColor || ""))
    ? String(input.accentColor)
    : "#14b8a6";

  const backgroundColor = /^#[0-9a-fA-F]{6}$/.test(
    String(input?.backgroundColor || "")
  )
    ? String(input.backgroundColor)
    : "#ffffff";

  const buttonColor = /^#[0-9a-fA-F]{6}$/.test(String(input?.buttonColor || ""))
    ? String(input.buttonColor)
    : accentColor;

  const imageUrl = String(input?.imageUrl || "").trim();
  const buttonLabel =
    String(input?.buttonLabel || "Tôi đã đọc & hiểu rõ").trim().slice(0, 80) ||
    "Tôi đã đọc & hiểu rõ";

  return {
    size,
    radius,
    accentColor,
    backgroundColor,
    buttonColor,
    imageUrl,
    buttonLabel,
  };
}

async function createStudentAccount(input, createdBy) {
  const name = cleanName(input?.name);
  if (!name) throw new Error("Họ và tên là bắt buộc.");

  let loginName = normalizeUsername(input?.username || input?.loginName);
  if (!loginName) loginName = slugify(name).replace(/-/g, "");
  if (!loginName) loginName = `member${Date.now()}`;

  let email = cleanEmail(input?.email);
  if (!email) email = `a8a8.${loginName}@${STUDENT_EMAIL_DOMAIN}`;
  if (!validEmail(email)) throw new Error("Email đăng nhập không hợp lệ.");

  const password = String(input?.password || "").trim() || randomPassword();
  if (password.length < 6) throw new Error("Mật khẩu phải có ít nhất 6 ký tự.");

  const aliasRef = db().collection("loginAliases").doc(loginName);
  const aliasSnap = await aliasRef.get();
  if (aliasSnap.exists && cleanEmail(aliasSnap.data()?.email) !== email) {
    throw new Error(`Tên tài khoản "${loginName}" đã được sử dụng.`);
  }

  let account = null;
  try {
    account = await auth().createUser({
      email,
      password,
      displayName: name,
    });

    const uid = account.uid;
    const dob = String(input?.dob || "");
    const gender = String(input?.gender || "");
    const team = String(input?.team || "");
    const classRole = String(input?.classRole || "Học sinh");

    const batch = db().batch();
    batch.set(db().collection("users").doc(uid), {
      uid,
      email,
      loginName,
      username: loginName,
      displayName: name,
      role: "student",
      classRole,
      team,
      studentId: uid,
      studentUid: uid,
      bio: "",
      photoURL: "",
      themeColors: null,
      createdAt: SERVER_TIMESTAMP(),
      updatedAt: SERVER_TIMESTAMP(),
      createdBy: createdBy || null,
    });

    batch.set(db().collection("students").doc(uid), {
      id: uid,
      uid,
      name,
      dob,
      gender,
      team,
      classRole,
      score: 10,
      badges: [],
      history: [],
      accountUid: uid,
      accountEmail: email,
      loginName,
      username: loginName,
      createdAt: SERVER_TIMESTAMP(),
      updatedAt: SERVER_TIMESTAMP(),
      createdBy: createdBy || null,
    });

    batch.set(aliasRef, {
      username: loginName,
      email,
      uid,
      displayName: name,
      updatedAt: SERVER_TIMESTAMP(),
    });

    await batch.commit();

    return {
      id: uid,
      uid,
      name,
      dob,
      gender,
      team,
      classRole,
      email,
      username: loginName,
      loginName,
      temporaryPassword: password,
      passwordProvided: Boolean(input?.password),
      accountUid: uid,
    };
  } catch (error) {
    if (account?.uid) {
      try {
        await auth().deleteUser(account.uid);
      } catch (rollbackError) {
        console.error("[Rollback Auth]", rollbackError?.message);
      }
    }

    if (error?.code === "auth/email-already-exists") {
      throw new Error(`Email ${email} đã tồn tại trong Firebase Authentication.`);
    }
    throw error;
  }
}

function onlySafeContent(body = {}) {
  const clone = { ...body };
  delete clone.createdAt;
  delete clone.createdBy;
  delete clone.updatedAt;
  return clone;
}

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "8A8 Class Portal Backend",
    timestamp: new Date().toISOString(),
    timezone: "Asia/Ho_Chi_Minh",
    firebaseReady,
    studentEmailDomain: STUDENT_EMAIL_DOMAIN,
  });
});

app.get("/api/runtime-config", (req, res) => {
  res.json({
    ok: true,
    superAdminEmail: SUPER_ADMIN_EMAIL,
    studentEmailDomain: STUDENT_EMAIL_DOMAIN,
  });
});

/** Public helper: cho phép học sinh dùng username được Admin cấp. */
app.get("/api/public/resolve-login", async (req, res) => {
  try {
    const username = normalizeUsername(req.query?.username);
    if (!username) return res.status(400).json({ message: "Thiếu username." });
    const snap = await db().collection("loginAliases").doc(username).get();
    if (!snap.exists) return res.status(404).json({ message: "Không tìm thấy tài khoản." });
    const value = snap.data() || {};
    return res.json({
      ok: true,
      username,
      email: cleanEmail(value.email),
    });
  } catch (error) {
    return sendError(res, 500, "Không thể tra cứu tên tài khoản.", error);
  }
});

/** Student poll vote: thực hiện bằng Admin SDK để không cho client tự sửa số vote. */
app.post("/api/polls/:id/vote", authenticated, async (req, res) => {
  try {
    const pollId = safeId(req.params.id);
    const optionId = safeId(req.body?.optionId);
    if (!pollId || !optionId) return res.status(400).json({ message: "Thiếu pollId hoặc optionId." });

    const pollRef = db().collection("polls").doc(pollId);
    const voteRef = db().collection("pollVotes").doc(`${pollId}_${req.user.uid}`);
    let result = null;

    await db().runTransaction(async (transaction) => {
      const [pollSnap, voteSnap] = await Promise.all([
        transaction.get(pollRef),
        transaction.get(voteRef),
      ]);
      if (!pollSnap.exists) throw new Error("Không tìm thấy Poll.");
      if (voteSnap.exists) {
        const duplicateError = new Error("Bạn đã bình chọn Poll này rồi.");
        duplicateError.code = "already-voted";
        throw duplicateError;
      }

      const poll = pollSnap.data() || {};
      if (poll.active === false) throw new Error("Poll này đã tạm dừng.");
      const options = Array.isArray(poll.options) ? poll.options.map((option) => ({ ...option })) : [];
      const index = options.findIndex((option) => String(option.id) === optionId);
      if (index < 0) throw new Error("Không tìm thấy lựa chọn Poll.");

      options[index].votes = Number(options[index].votes || 0) + 1;
      transaction.update(pollRef, { options, updatedAt: SERVER_TIMESTAMP() });
      transaction.set(voteRef, {
        pollId,
        optionId,
        uid: req.user.uid,
        createdAt: SERVER_TIMESTAMP(),
      });
      result = { optionId, votes: options[index].votes };
    });

    return res.json({ ok: true, ...result });
  } catch (error) {
    if (error?.code === "already-voted") {
      return res.status(409).json({ message: error.message });
    }
    return sendError(res, 400, "Không thể ghi nhận bình chọn.", error);
  }
});

/** CRITICAL: frontend gọi endpoint này sau khi Firebase Auth đã có user. */
app.get("/api/admin/verify", authenticated, async (req, res) => {
  try {
    const result = await resolveAdminProfile(req.user);
    if (!result.allowed) {
      return res.status(403).json({
        ok: false,
        allowed: false,
        message: "Tài khoản này không có quyền quản trị.",
        uid: req.user.uid,
        email: cleanEmail(req.user.email),
        role: result.role,
        source: result.source,
      });
    }

    return res.json({
      ok: true,
      allowed: true,
      uid: req.user.uid,
      email: cleanEmail(req.user.email),
      role: result.role,
      source: result.source,
      profile: result.profile,
    });
  } catch (error) {
    return sendError(res, 500, "Backend không thể hoàn thành bước xác minh Admin.", error);
  }
});

app.post("/api/admin/students/create", authenticated, adminOnly, async (req, res) => {
  try {
    const student = await createStudentAccount(req.body, req.user.uid);
    return res.status(201).json({ ok: true, student });
  } catch (error) {
    return sendError(res, 400, "Không thể tạo tài khoản học sinh.", error);
  }
});

app.post("/api/admin/students/create-bulk", authenticated, adminOnly, async (req, res) => {
  try {
    const rows = Array.isArray(req.body?.students) ? req.body.students : [];
    if (!rows.length) return res.status(400).json({ message: "Danh sách thành viên trống." });
    if (rows.length > 100) {
      return res.status(400).json({ message: "Mỗi lần chỉ được tạo tối đa 100 tài khoản." });
    }

    const created = [];
    const failed = [];
    for (let index = 0; index < rows.length; index += 1) {
      try {
        created.push(await createStudentAccount(rows[index], req.user.uid));
      } catch (error) {
        failed.push({
          row: index + 1,
          name: cleanName(rows[index]?.name),
          email: cleanEmail(rows[index]?.email),
          username: normalizeUsername(rows[index]?.username || rows[index]?.loginName),
          message: error?.message || "Lỗi không xác định.",
        });
      }
    }

    return res.json({
      ok: failed.length === 0,
      created,
      failed,
      total: rows.length,
    });
  } catch (error) {
    return sendError(res, 500, "Không thể xử lý danh sách hàng loạt.", error);
  }
});

app.patch("/api/admin/students/:id", authenticated, adminOnly, async (req, res) => {
  try {
    const id = safeId(req.params.id);
    const ref = db().collection("students").doc(id);
    const snap = await ref.get();
    if (!snap.exists) return res.status(404).json({ message: "Không tìm thấy học sinh." });

    const current = snap.data() || {};
    const uid = safeId(current.accountUid || current.studentUid || current.uid || id);

    const patch = {};
    for (const key of ["name", "dob", "gender", "team", "classRole", "accountEmail", "loginName", "username"]) {
      if (req.body?.[key] !== undefined) patch[key] = req.body[key];
    }

    const currentLoginName = normalizeUsername(current.loginName || current.username || "");
    const requestedLoginName = patch.loginName ?? patch.username;
    const nextLoginName = requestedLoginName !== undefined
      ? normalizeUsername(requestedLoginName)
      : currentLoginName;

    const currentEmail = cleanEmail(current.accountEmail || current.email || "");
    const requestedEmail = patch.accountEmail;
    const nextEmail = requestedEmail !== undefined
      ? cleanEmail(requestedEmail)
      : currentEmail;

    if (requestedEmail !== undefined && !validEmail(nextEmail)) {
      return res.status(400).json({ message: "Email tài khoản không hợp lệ." });
    }

    if (requestedLoginName !== undefined && !nextLoginName) {
      return res.status(400).json({ message: "Tên tài khoản không hợp lệ." });
    }

    const oldAliasRef = currentLoginName ? db().collection("loginAliases").doc(currentLoginName) : null;
    const newAliasRef = nextLoginName ? db().collection("loginAliases").doc(nextLoginName) : null;

    if (nextLoginName && nextLoginName !== currentLoginName) {
      const aliasSnap = await newAliasRef.get();
      if (aliasSnap.exists && safeId(aliasSnap.data()?.uid) !== uid) {
        return res.status(409).json({ message: "Tên tài khoản đã được sử dụng." });
      }
    }

    if (uid) {
      const authPatch = {};
      if (patch.name) authPatch.displayName = cleanName(patch.name);
      if (requestedEmail !== undefined) authPatch.email = nextEmail;
      if (Object.keys(authPatch).length) await auth().updateUser(uid, authPatch);

      const userPatch = { updatedAt: SERVER_TIMESTAMP() };
      if (patch.name !== undefined) userPatch.displayName = cleanName(patch.name);
      if (requestedEmail !== undefined) userPatch.email = nextEmail;
      if (patch.team !== undefined) userPatch.team = patch.team;
      if (patch.classRole !== undefined) userPatch.classRole = patch.classRole;
      if (requestedLoginName !== undefined || currentLoginName) {
        userPatch.loginName = nextLoginName;
        userPatch.username = nextLoginName;
      }
      await db().collection("users").doc(uid).set(userPatch, { merge: true });

      if (oldAliasRef && currentLoginName !== nextLoginName) {
        await oldAliasRef.delete();
      }
      if (newAliasRef && nextLoginName) {
        await newAliasRef.set({ uid, email: nextEmail, username: nextLoginName, updatedAt: SERVER_TIMESTAMP() }, { merge: true });
      }
    }

    if (requestedEmail !== undefined) patch.accountEmail = nextEmail;
    if (requestedLoginName !== undefined || currentLoginName) {
      patch.loginName = nextLoginName;
      patch.username = nextLoginName;
    }
    patch.updatedAt = SERVER_TIMESTAMP();
    await ref.set(patch, { merge: true });

    return res.json({ ok: true, current: { ...current, ...patch } });
  } catch (error) {
    return sendError(res, 400, "Không thể cập nhật học sinh.", error);
  }
});

app.patch("/api/admin/students/:id/score", authenticated, adminOnly, async (req, res) => {
  try {
    const id = safeId(req.params.id);
    const points = Number(req.body?.points);
    const reason = String(req.body?.reason || "").trim();
    const type = ["praise", "reminder", "criticism"].includes(String(req.body?.type))
      ? String(req.body.type)
      : points >= 0
        ? "praise"
        : "criticism";

    if (!id || !Number.isFinite(points) || points === 0 || Math.abs(points) > 100 || !reason) {
      return res.status(400).json({ message: "Số điểm hoặc lý do không hợp lệ." });
    }

    const studentRef = db().collection("students").doc(id);
    const userRef = db().collection("users").doc(id);
    const notificationRef = db().collection("notifications").doc();
    const pointLogRef = db().collection("pointLogs").doc();

    let result = null;

    await db().runTransaction(async (transaction) => {
      const snap = await transaction.get(studentRef);
      if (!snap.exists) throw new Error("Không tìm thấy học sinh.");
      const old = snap.data() || {};
      const oldScore = Number(old.score ?? 10);
      const newScore = oldScore + points;
      const entry = {
        type,
        points,
        reason,
        byUid: req.user.uid,
        byEmail: cleanEmail(req.user.email),
        timestamp: new Date().toISOString(),
      };

      const history = Array.isArray(old.history) ? old.history : [];
      transaction.update(studentRef, {
        score: newScore,
        history: [...history, entry].slice(-100),
        updatedAt: SERVER_TIMESTAMP(),
      });

      transaction.set(pointLogRef, {
        studentUid: id,
        points,
        previousScore: oldScore,
        newScore,
        type,
        reason,
        byUid: req.user.uid,
        byEmail: cleanEmail(req.user.email),
        createdAt: SERVER_TIMESTAMP(),
      });

      transaction.set(notificationRef, {
        recipientUid: id,
        category: "score",
        type,
        points,
        title:
          type === "praise"
            ? "🎉 Khen thưởng"
            : type === "reminder"
              ? "⚠️ Nhắc nhở"
              : "❌ Phê bình",
        message: reason,
        read: false,
        createdAt: SERVER_TIMESTAMP(),
        createdBy: req.user.uid,
        pointLogId: pointLogRef.id,
      });

      transaction.set(
        userRef,
        {
          updatedAt: SERVER_TIMESTAMP(),
          lastNotificationAt: SERVER_TIMESTAMP(),
        },
        { merge: true }
      );

      result = {
        notificationId: notificationRef.id,
        pointLogId: pointLogRef.id,
        previousScore: oldScore,
        newScore,
      };
    });

    return res.json({ ok: true, ...result });
  } catch (error) {
    return sendError(res, 500, "Không thể cập nhật điểm thi đua.", error);
  }
});

app.post("/api/admin/students/:id/reset-password", authenticated, adminOnly, async (req, res) => {
  try {
    const id = safeId(req.params.id);
    const snap = await db().collection("students").doc(id).get();
    if (!snap.exists) return res.status(404).json({ message: "Không tìm thấy học sinh." });

    const student = snap.data() || {};
    const uid = safeId(student.accountUid || student.studentUid || student.uid || id);
    const target = await auth().getUser(uid);

    if (cleanEmail(target.email) === SUPER_ADMIN_EMAIL) {
      return res.status(403).json({ message: "Không được đổi mật khẩu Super Admin chính." });
    }

    const password = String(req.body?.password || "").trim() || randomPassword();
    if (password.length < 6) return res.status(400).json({ message: "Mật khẩu tối thiểu 6 ký tự." });

    await auth().updateUser(uid, { password });
    await db().collection("users").doc(uid).set(
      {
        passwordResetAt: SERVER_TIMESTAMP(),
        passwordResetBy: req.user.uid,
        updatedAt: SERVER_TIMESTAMP(),
      },
      { merge: true }
    );

    return res.json({
      ok: true,
      uid,
      email: target.email,
      username: student.username || student.loginName || "",
      temporaryPassword: password,
    });
  } catch (error) {
    return sendError(res, 400, "Không thể cấp lại mật khẩu.", error);
  }
});

app.delete("/api/admin/students/:id", authenticated, adminOnly, async (req, res) => {
  try {
    const id = safeId(req.params.id);
    const studentRef = db().collection("students").doc(id);
    const snap = await studentRef.get();
    if (!snap.exists) return res.status(404).json({ message: "Không tìm thấy học sinh." });

    const student = snap.data() || {};
    const uid = safeId(student.accountUid || student.studentUid || student.uid || id);
    if (uid) {
      const target = await auth().getUser(uid);
      if (cleanEmail(target.email) === SUPER_ADMIN_EMAIL) {
        return res.status(403).json({ message: "Không được xóa Super Admin chính." });
      }
      await auth().deleteUser(uid).catch((error) => {
        if (error?.code !== "auth/user-not-found") throw error;
      });
    }

    const batch = db().batch();
    batch.delete(studentRef);
    if (uid) batch.delete(db().collection("users").doc(uid));
    if (student.loginName || student.username) {
      batch.delete(
        db().collection("loginAliases").doc(
          normalizeUsername(student.loginName || student.username)
        )
      );
    }
    await batch.commit();
    return res.json({ ok: true });
  } catch (error) {
    return sendError(res, 500, "Không thể xóa học sinh và tài khoản liên kết.", error);
  }
});

app.post("/api/admin/popup", authenticated, adminOnly, async (req, res) => {
  try {
    const title = String(req.body?.title || "").trim();
    const content = String(req.body?.content || "").trim();
    if (!title || !content) {
      return res.status(400).json({ message: "Tiêu đề và nội dung Popup là bắt buộc." });
    }

    const style = sanitizePopupStyle(req.body);
    const ref = await db().collection("popups").add({
      title,
      content,
      active: req.body?.active !== false,
      ...style,
      createdBy: req.user.uid,
      createdAt: SERVER_TIMESTAMP(),
      updatedAt: SERVER_TIMESTAMP(),
      dailyResetNonce: Date.now(),
    });
    return res.status(201).json({ ok: true, id: ref.id });
  } catch (error) {
    return sendError(res, 400, "Không thể tạo Popup.", error);
  }
});

app.post("/api/admin/popup/reset", authenticated, adminOnly, async (req, res) => {
  try {
    const snap = await db().collection("popups").where("active", "==", true).get();
    const batch = db().batch();
    snap.docs.forEach((docSnap) =>
      batch.update(docSnap.ref, {
        dailyResetNonce: Date.now(),
        dailyResetAt: SERVER_TIMESTAMP(),
        updatedAt: SERVER_TIMESTAMP(),
      })
    );
    if (snap.size) await batch.commit();
    return res.json({ ok: true, count: snap.size });
  } catch (error) {
    return sendError(res, 500, "Không thể reset trạng thái Popup.", error);
  }
});

app.post("/api/admin/notification", authenticated, adminOnly, async (req, res) => {
  try {
    const recipientUid = safeId(req.body?.recipientUid);
    const type = ["praise", "reminder", "criticism"].includes(String(req.body?.type))
      ? String(req.body.type)
      : "reminder";
    const title = String(req.body?.title || "").trim() ||
      (type === "praise" ? "🎉 Khen thưởng" : type === "reminder" ? "⚠️ Nhắc nhở" : "❌ Phê bình");
    const message = String(req.body?.message || "").trim();
    if (!recipientUid || !message) return res.status(400).json({ message: "Thiếu học sinh hoặc lời nhắn." });

    const ref = await db().collection("notifications").add({
      recipientUid,
      category: "private",
      type,
      title,
      message,
      read: false,
      createdAt: SERVER_TIMESTAMP(),
      createdBy: req.user.uid,
      createdByEmail: cleanEmail(req.user.email),
    });
    return res.status(201).json({ ok: true, id: ref.id });
  } catch (error) {
    return sendError(res, 400, "Không thể gửi lời nhắn riêng.", error);
  }
});

app.post("/api/admin/content/:collection", authenticated, adminOnly, async (req, res) => {
  try {
    const collectionName = safeId(req.params.collection);
    if (!CONTENT_COLLECTIONS.has(collectionName)) {
      return res.status(400).json({ message: `Collection ${collectionName} không được phép.` });
    }

    const payload = onlySafeContent(req.body || {});
    payload.createdBy = req.user.uid;
    payload.createdByEmail = cleanEmail(req.user.email);
    payload.createdAt = SERVER_TIMESTAMP();
    payload.updatedAt = SERVER_TIMESTAMP();

    const ref = await db().collection(collectionName).add(payload);
    return res.status(201).json({ ok: true, id: ref.id });
  } catch (error) {
    return sendError(res, 500, `Không thể tạo dữ liệu trong ${req.params.collection}.`, error);
  }
});

app.patch("/api/admin/content/:collection/:id", authenticated, adminOnly, async (req, res) => {
  try {
    const collectionName = safeId(req.params.collection);
    const id = safeId(req.params.id);
    if (!CONTENT_COLLECTIONS.has(collectionName)) {
      return res.status(400).json({ message: `Collection ${collectionName} không được phép.` });
    }
    if (!id) return res.status(400).json({ message: "Thiếu id." });

    const patch = onlySafeContent(req.body || {});
    patch.updatedAt = SERVER_TIMESTAMP();
    await db().collection(collectionName).doc(id).update(patch);
    return res.json({ ok: true });
  } catch (error) {
    return sendError(res, 500, "Không thể cập nhật dữ liệu.", error);
  }
});

app.delete("/api/admin/content/:collection/:id", authenticated, adminOnly, async (req, res) => {
  try {
    const collectionName = safeId(req.params.collection);
    const id = safeId(req.params.id);
    if (!CONTENT_COLLECTIONS.has(collectionName)) {
      return res.status(400).json({ message: `Collection ${collectionName} không được phép.` });
    }
    if (!id) return res.status(400).json({ message: "Thiếu id." });

    await db().collection(collectionName).doc(id).delete();
    return res.json({ ok: true });
  } catch (error) {
    return sendError(res, 500, "Không thể xóa dữ liệu.", error);
  }
});

app.patch("/api/super-admin/users/:uid/role", authenticated, adminOnly, superOnly, async (req, res) => {
  try {
    const uid = safeId(req.params.uid);
    const role = safeId(req.body?.role);
    if (!uid || !["student", "admin"].includes(role)) {
      return res.status(400).json({ message: "uid hoặc role không hợp lệ." });
    }

    const target = await auth().getUser(uid);
    if (cleanEmail(target.email) === SUPER_ADMIN_EMAIL) {
      return res.status(403).json({ message: "Không được hạ quyền Super Admin chính." });
    }

    await db().collection("users").doc(uid).set(
      { role, updatedAt: SERVER_TIMESTAMP(), updatedBy: req.user.uid },
      { merge: true }
    );
    await auth().setCustomUserClaims(uid, { role, admin: role === "admin" });

    return res.json({ ok: true, uid, role });
  } catch (error) {
    return sendError(res, 400, "Không thể đổi role.", error);
  }
});

app.delete("/api/admin/chat/rooms/:roomId", authenticated, adminOnly, async (req, res) => {
  try {
    const roomId = safeId(req.params.roomId);
    if (!roomId) return res.status(400).json({ message: "Thiếu roomId." });
    const roomRef = db().collection("chatRooms").doc(roomId);
    if (typeof db().recursiveDelete === "function") {
      await db().recursiveDelete(roomRef);
    } else {
      await roomRef.delete();
    }
    return res.json({ ok: true });
  } catch (error) {
    return sendError(res, 500, "Không thể xóa phòng chat.", error);
  }
});

app.delete("/api/admin/chat/rooms/:roomId/messages/:messageId", authenticated, adminOnly, async (req, res) => {
  try {
    const roomId = safeId(req.params.roomId);
    const messageId = safeId(req.params.messageId);
    if (!roomId || !messageId) return res.status(400).json({ message: "Thiếu roomId hoặc messageId." });
    await db().collection("chatRooms").doc(roomId).collection("messages").doc(messageId).delete();
    return res.json({ ok: true });
  } catch (error) {
    return sendError(res, 500, "Không thể xóa tin nhắn.", error);
  }
});

app.patch("/api/admin/chat/rooms/:roomId/lock", authenticated, adminOnly, async (req, res) => {
  try {
    const roomId = safeId(req.params.roomId);
    const locked = Boolean(req.body?.locked);
    await db().collection("chatRooms").doc(roomId).update({ locked, updatedAt: SERVER_TIMESTAMP() });
    return res.json({ ok: true, locked });
  } catch (error) {
    return sendError(res, 500, "Không thể khóa/mở phòng chat.", error);
  }
});

app.get("/manifest.webmanifest", (req, res) => {
  res
    .type("application/manifest+json")
    .send(
      JSON.stringify({
        name: "Portal 8A8 - Trường THCS Cẩm Lý 2",
        short_name: "Portal 8A8",
        start_url: "/index.html#trang-chu",
        scope: "/",
        display: "standalone",
        background_color: "#f1f5f9",
        theme_color: "#14b8a6",
        description: "Cổng thông tin lớp 8A8 - Trường THCS Cẩm Lý 2.",
        icons: [
          {
            src: "/logo.png",
            sizes: "500x500",
            type: "image/png",
            purpose: "any maskable",
          },
        ],
      })
    );
});

app.get("/admin.html", (req, res) => res.sendFile(path.join(__dirname, "admin.html")));
app.get("/admin", (req, res) => res.sendFile(path.join(__dirname, "admin.html")));
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));

app.listen(PORT, () => {
  console.log(`Portal 8A8 backend listening on ${PORT}`);
});
