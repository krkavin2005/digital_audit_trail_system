const AuditEvent = require("../models/AuditEvent");
const { computeHash } = require("../utils/hash");
const updateAuditAnchor = require("../utils/updateAuditAnchor");
const fs = require("fs");

async function getPreviousHash() {
    const lastEvent = await AuditEvent.findOne({}).sort({ timestamp: -1 }).lean();
    return lastEvent ? lastEvent.hash : "0".repeat(64);
}

async function recordEvent(actorId, actor, actorRole, action, target) {
    const prevHash = await getPreviousHash();
    const last = await AuditEvent.findOne({}).sort({ eventId: -1 });
    const eventId = last ? last.eventId + 1 : 1;
    const event = {
        eventId,
        actorId,
        actor,
        actorRole,
        action,
        target,
        timestamp: new Date()
    };
    const hash = computeHash(event, prevHash);
    await AuditEvent.create({ ...event, prevHash, hash });
    console.log("Recorded: ", hash);
    updateAuditAnchor(hash, eventId);
}

async function verifyAuditLog() {
    const anchor = JSON.parse(fs.readFileSync("audit-anchor.json", "utf8"));
    const events = await AuditEvent.find({}).sort({ eventId: 1 }).lean();
    const lastEvent = events[events.length - 1];
    if (anchor.lastHash !== lastEvent.hash) {
        return {
            valid: false,
            brokenAt: events.length - 1,
            expectedHash: anchor.lastHash,
            found: lastEvent.hash,
            expectedCount: anchor.eventCount,
            presentCount: events.length,
            tamperCode: 2
        };
    }
    if (events.length === 0) {
        return { valid: true, message: "No audit events found" };
    }
    let storedPrevHash = "0".repeat(64);
    for (let i = 0; i < events.length; i++) {
        const { _id, hash, prevHash, ...eventData } = events[i];
        if (storedPrevHash !== prevHash) {
            return {
                valid: false,
                brokenAt: i,
                expectedPrevHash: storedPrevHash,
                foundPrevHash: prevHash,
                tamperCode: 0
            }
        }
        const recomputedHash = computeHash(eventData, prevHash);
        if (recomputedHash !== hash) {
            return {
                valid: false,
                brokenAt: i,
                expected: recomputedHash,
                found: hash,
                tamperCode: 1
            };
        }
        storedPrevHash = hash;
    }
    return { valid: true };
}

async function getAuditLogs(obj) {
    return await AuditEvent.find(obj).sort({ eventId: 1 }).lean();
}

async function logAction(user, action, target) {
    const { userId, username, role } = user;
    const actorRole = role.roleName;
    const actor = username;
    const actorId = userId;
    await recordEvent(actorId, actor, actorRole, action, target);
}

module.exports = { recordEvent , verifyAuditLog , getAuditLogs , logAction};