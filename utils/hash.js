const crypto = require("crypto");

function canonicalStringify(obj) {
    return JSON.stringify(Object.keys(obj).sort().reduce((acc, key) => {
        acc[key] = obj[key];
        return acc;
    }, {}))
}

function computeHash(eventData, prevHash) {
    const payload = canonicalStringify(eventData);
    return crypto.createHash("sha256").update(payload + prevHash).digest("hex");
}

module.exports = {computeHash , canonicalStringify};