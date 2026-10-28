// rpyc-face-api — RPYC Visitor POC face service
// Actions (POST JSON): ping | search | enrol | listFaces (admin) | delete (admin)
// Every request must carry a Microsoft Entra ID token: "Authorization: Bearer <id token>"
// Photos are never stored here — only Rekognition face prints, tagged with the SharePoint visitor ID.

import {
  RekognitionClient,
  DetectFacesCommand,
  SearchFacesByImageCommand,
  IndexFacesCommand,
  DeleteFacesCommand,
  ListFacesCommand,
} from "@aws-sdk/client-rekognition";
import crypto from "node:crypto";

const TENANT_ID = process.env.TENANT_ID;
const CLIENT_ID = process.env.CLIENT_ID;
const COLLECTION_ID = process.env.COLLECTION_ID || "rpyc-visitors";
const MATCH_THRESHOLD = Number(process.env.MATCH_THRESHOLD || 90);
// Comma-separated sign-in names allowed to run housekeeping, e.g. "mscully@concept.com.pg"
const ADMIN_USERS = (process.env.ADMIN_USERS || "")
  .toLowerCase()
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const rek = new RekognitionClient({});

class AuthError extends Error {}
class ForbiddenError extends Error {}
class UserError extends Error {
  constructor(message, code) {
    super(message);
    this.code = code;
  }
}

const reply = (statusCode, obj) => ({
  statusCode,
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(obj),
});

// ---------- Microsoft token check ----------

let jwksCache = null;
let jwksFetchedAt = 0;

async function getSigningKeys(force = false) {
  const sixHours = 6 * 60 * 60 * 1000;
  if (!force && jwksCache && Date.now() - jwksFetchedAt < sixHours) return jwksCache;
  const res = await fetch(`https://login.microsoftonline.com/${TENANT_ID}/discovery/v2.0/keys`);
  if (!res.ok) throw new Error(`Could not fetch Microsoft signing keys (${res.status})`);
  jwksCache = (await res.json()).keys;
  jwksFetchedAt = Date.now();
  return jwksCache;
}

const b64url = (s) => Buffer.from(s, "base64url");

async function verifyToken(authHeader) {
  if (!authHeader || !authHeader.startsWith("Bearer ")) throw new AuthError("Missing sign-in token");
  const token = authHeader.slice(7).trim();
  const parts = token.split(".");
  if (parts.length !== 3) throw new AuthError("Malformed token");

  let header, payload;
  try {
    header = JSON.parse(b64url(parts[0]).toString("utf8"));
    payload = JSON.parse(b64url(parts[1]).toString("utf8"));
  } catch {
    throw new AuthError("Malformed token");
  }
  if (header.alg !== "RS256") throw new AuthError("Unexpected token algorithm");

  let keys = await getSigningKeys();
  let jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk) {
    keys = await getSigningKeys(true); // Microsoft rotates keys; refresh once
    jwk = keys.find((k) => k.kid === header.kid);
  }
  if (!jwk) throw new AuthError("Unknown signing key");

  const publicKey = crypto.createPublicKey({ key: { kty: jwk.kty, n: jwk.n, e: jwk.e }, format: "jwk" });
  const signatureOk = crypto.verify(
    "RSA-SHA256",
    Buffer.from(`${parts[0]}.${parts[1]}`),
    publicKey,
    b64url(parts[2])
  );
  if (!signatureOk) throw new AuthError("Invalid token signature");

  const now = Math.floor(Date.now() / 1000);
  if (!payload.exp || now > payload.exp + 60) throw new AuthError("Token expired");
  if (payload.nbf && now < payload.nbf - 60) throw new AuthError("Token not yet valid");
  if (payload.aud !== CLIENT_ID) throw new AuthError("Token is for a different app");
  if (payload.tid !== TENANT_ID) throw new AuthError("Token is from a different organisation");
  if (payload.iss !== `https://login.microsoftonline.com/${TENANT_ID}/v2.0`) throw new AuthError("Unexpected token issuer");

  return payload;
}

// ---------- Face helpers ----------

function imageBytes(b64) {
  if (!b64) throw new UserError("No photo supplied", "NO_IMAGE");
  const clean = String(b64).replace(/^data:image\/\w+;base64,/, "");
  const bytes = Buffer.from(clean, "base64");
  if (bytes.length < 1000) throw new UserError("Photo is empty or unreadable", "BAD_IMAGE");
  if (bytes.length > 4.5 * 1024 * 1024) throw new UserError("Photo is too large", "TOO_LARGE");
  return bytes;
}

async function requireOneFace(bytes) {
  const r = await rek.send(new DetectFacesCommand({ Image: { Bytes: bytes } }));
  const faces = (r.FaceDetails || []).filter((f) => f.Confidence >= 90);
  if (faces.length === 0) throw new UserError("No face found. Ask the visitor to look at the camera.", "NO_FACE");
  if (faces.length > 1) throw new UserError("More than one face in the photo. Only the visitor should be in frame.", "MULTIPLE_FACES");
}

function rekognitionInputError(err) {
  if (err?.name === "InvalidParameterException" || err?.name === "InvalidImageFormatException") {
    return new UserError("The photo wasn't clear enough. Please retake it.", "LOW_QUALITY");
  }
  return err;
}

async function searchFace(b64) {
  const bytes = imageBytes(b64);
  await requireOneFace(bytes);
  try {
    const r = await rek.send(
      new SearchFacesByImageCommand({
        CollectionId: COLLECTION_ID,
        Image: { Bytes: bytes },
        FaceMatchThreshold: MATCH_THRESHOLD,
        MaxFaces: 1,
        QualityFilter: "AUTO",
      })
    );
    const m = r.FaceMatches?.[0];
    if (!m) return { match: false };
    return {
      match: true,
      visitorId: m.Face.ExternalImageId,
      faceId: m.Face.FaceId,
      similarity: Math.round(m.Similarity * 10) / 10,
    };
  } catch (err) {
    throw rekognitionInputError(err);
  }
}

async function enrolFace(b64, visitorId) {
  const id = String(visitorId ?? "");
  if (!/^[A-Za-z0-9_.\-:]{1,255}$/.test(id)) throw new UserError("Missing or invalid visitorId", "BAD_VISITOR_ID");
  const bytes = imageBytes(b64);
  await requireOneFace(bytes);
  try {
    const r = await rek.send(
      new IndexFacesCommand({
        CollectionId: COLLECTION_ID,
        Image: { Bytes: bytes },
        ExternalImageId: id,
        MaxFaces: 1,
        QualityFilter: "AUTO",
        DetectionAttributes: [],
      })
    );
    const rec = r.FaceRecords?.[0];
    if (!rec) throw new UserError("The face wasn't clear enough to enrol. Please retake the photo.", "LOW_QUALITY");
    return { faceId: rec.Face.FaceId, visitorId: id };
  } catch (err) {
    throw rekognitionInputError(err);
  }
}

async function deleteFaces(faceIds) {
  if (!Array.isArray(faceIds) || faceIds.length === 0 || faceIds.length > 4096) {
    throw new UserError("Supply faceIds as a list of 1 to 4096 IDs", "BAD_FACE_IDS");
  }
  const r = await rek.send(new DeleteFacesCommand({ CollectionId: COLLECTION_ID, FaceIds: faceIds }));
  return { deleted: r.DeletedFaces || [] };
}

async function listAllFaces() {
  const faces = [];
  let NextToken;
  do {
    const r = await rek.send(new ListFacesCommand({ CollectionId: COLLECTION_ID, MaxResults: 1000, NextToken }));
    for (const f of r.Faces || []) faces.push({ faceId: f.FaceId, visitorId: f.ExternalImageId || "" });
    NextToken = r.NextToken;
  } while (NextToken);
  return { faces };
}

function isAdmin(user) {
  const name = String(user.preferred_username || user.email || "").toLowerCase();
  return !!name && ADMIN_USERS.includes(name);
}

function requireAdmin(user) {
  if (!isAdmin(user)) throw new ForbiddenError("Only administrators can do this");
}

// ---------- Entry point ----------

export const handler = async (event) => {
  try {
    if (!TENANT_ID || !CLIENT_ID) throw new Error("TENANT_ID and CLIENT_ID environment variables must be set");
    if (event.requestContext?.http?.method !== "POST") return reply(405, { error: "Use POST" });

    const user = await verifyToken(event.headers?.authorization);

    let body = event.body || "{}";
    if (event.isBase64Encoded) body = Buffer.from(body, "base64").toString("utf8");
    let req;
    try {
      req = JSON.parse(body);
    } catch {
      return reply(400, { error: "Body must be JSON", code: "BAD_JSON" });
    }

    switch (req.action) {
      case "ping":
        return reply(200, { ok: true, user: user.preferred_username || user.name || "unknown", admin: isAdmin(user) });
      case "search":
        return reply(200, await searchFace(req.image));
      case "enrol":
        return reply(200, await enrolFace(req.image, req.visitorId));
      case "listFaces":
        requireAdmin(user);
        return reply(200, await listAllFaces());
      case "delete":
        requireAdmin(user);
        return reply(200, await deleteFaces(req.faceIds));
      default:
        return reply(400, { error: "Unknown action", code: "BAD_ACTION" });
    }
  } catch (err) {
    if (err instanceof AuthError) return reply(401, { error: err.message, code: "UNAUTHORISED" });
    if (err instanceof ForbiddenError) return reply(403, { error: err.message, code: "FORBIDDEN" });
    if (err instanceof UserError) return reply(400, { error: err.message, code: err.code });
    console.error(err);
    return reply(500, { error: "Server error", code: "SERVER_ERROR" });
  }
};
