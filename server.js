import express from "express";
import admin from "firebase-admin";
import cors from "cors";
import { createRequire } from "module";
import Joi from "joi";

const require = createRequire(import.meta.url);

// 🔐 Load Firebase Admin key
const serviceAccount = require("./serviceAccountKey.json");
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});
const db = admin.firestore();

const app = express();
app.use(cors());
app.use(express.json());

const ROLE = ["sales associate", "Manager", "admin", "OPS Head"];

const CITY = ["CHENNAI"];

function convertGMTtoISTFormatted(gmtString) {
  // Create date from GMT string
  const gmtDate = new Date(gmtString);

  // IST offset = UTC + 5 hours 30 minutes
  const istOffset = 5.5 * 60 * 60 * 1000;

  // Convert to IST
  const istDate = new Date(gmtDate.getTime() + istOffset);

  // Format: Mon D, YYYY
  const options = {
    month: "short",
    day: "numeric",
    year: "numeric",
  };

  return istDate.toLocaleDateString("en-US", options);
}

async function addLoginCredential(email, displayName, role, city) {
  try {
    const snapshot = await db.collection("LoginCredentials").limit(1).get();

    if (snapshot.empty) {
      throw new Error("No document found in LoginCredentials");
    }

    const docRef = snapshot.docs[0].ref;
    const docData = snapshot.docs[0].data();

    if (docData[email]) {
      throw new Error(`Email ${email} already exists`);
    }

    await docRef.set(
      {
        [email]: [displayName, email, role, city],
      },
      { merge: true }
    );

    return { success: true, message: `Added ${email} successfully` };
  } catch (error) {
    // rethrow so caller can handle it
    throw error;
  }
}

const createUserSchema = Joi.object({
  email: Joi.string().email().required(),

  password: Joi.string().min(6).required(),

  displayName: Joi.string().min(3).required(),

  Role: Joi.string()
    .valid(...ROLE)
    .required()
    .messages({
      "any.only": `Role must be one of: ${ROLE.join(", ")}`,
    }),

  City: Joi.string()
    .valid(...CITY)
    .required()
    .messages({
      "any.only": `City must be one of: ${CITY.join(", ")}`,
    }),
});

// 🔐 SIMPLE BEARER TOKEN (generate once & keep secret)
const API_TOKEN =
  "39dd3954c00c5132153c267a818a08c22d80931a8a5a8ac12facf18964066456";

// 🔐 Bearer middleware
function verifyBearer(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      message: "Unauthorized: Missing Bearer token",
    });
  }

  const token = authHeader.split("Bearer ")[1];

  if (token !== API_TOKEN) {
    return res.status(403).json({
      message: "Forbidden: Invalid token",
    });
  }

  next();
}

// ✅ Root endpoint
app.get("/", (req, res) => {
  res.send("Root end point is working fine!");
});

// 🔐 Protected Firebase users endpoint
app.get("/auth-users", verifyBearer, async (req, res) => {
  try {
    const users = [];
    let nextPageToken;

    do {
      const result = await admin.auth().listUsers(200, nextPageToken);

      result.users.forEach((user) => {
        users.push({
          uid: user.uid,
          email: user.email,
          providers: user.providerData.map((p) => p.providerId),
          createdAt: convertGMTtoISTFormatted(user.metadata.creationTime),
          lastLogin: convertGMTtoISTFormatted(user.metadata.lastSignInTime),
        });
      });

      nextPageToken = result.pageToken;
    } while (nextPageToken);

    res.status(200).send({
      total: users.length,
      users,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/create-user", verifyBearer, async (req, res) => {
  try {
    const { error, value } = createUserSchema.validate(req.body, {
      abortEarly: false,
    });

    if (error) {
      return res.status(400).json({
        message: "Validation failed",
        errors: error.details.map((err) => err.message),
      });
    }

    const { email, password, displayName, Role, City } = value;

    const userRecord = await admin.auth().createUser({
      email,
      password,
      displayName,
      emailVerified: true,
    });

    await addLoginCredential(email, displayName, Role, City);

    res.status(201).json({
      message: "User created successfully",
      user: {
        uid: userRecord.uid,
        email: userRecord.email,
        displayName: userRecord.displayName,
        Role,
        City,
      },
    });
  } catch (error) {
    res.status(400).json({
      message: error.message,
    });
  }
});

// 🚀 Start server
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
