const VerificationReport = require("../models/VerificationReport");
const { logAction } = require("../services/auditService");
const { generateVerificationReport, generatePDFReport, extractText, normalize, verifySignature, getPublicKeyFingerprint } = require("../services/reportService");

exports.verifyLogs = async (req, res) => {
    try {
        const result = await verifyAuditLog();
        await logAction(req.user, "AUDIT_VERIFICATION", "audit_log_chain");
        res.status(200).json({ result });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
};

exports.generateReport = async (req, res) => {
    let report;
    try {
        report = await generateVerificationReport();
        await logAction(req.user, "REPORT_GENERATED", report.reportId);
        res.json(report);
    } catch (err) {
        res.status(500).json({ err: err.message });
    }
};

exports.downloadReport = async (req, res) => {
    let report;
    try {
        const { reportId } = req.params;
        report = await VerificationReport.findOne({ reportId }).lean();
        if (!report) return res.status(404).json({ message: "Report not found" });
        await logAction(req.user, "REPORT_DOWNLOADED", report.reportId);
        generatePDFReport (report.renderedString, report.signature, res);
    } catch (err) {
        res.status(500).json({ err: err.message });
    }
};

exports.uploadReport = async (req, res) => {
    try {
        console.log("hi");
        
        if (!req.file) {
            return res.status(400).json({
                status: "INVALID REQUEST",
                message: "No file uploaded"
            });
        }
        const buffer = req.file.buffer;
        const text = await extractText(buffer);
        const signatureMatch = text.match(/BEGIN([\s\S]*?)END/);
        if (!signatureMatch) {
            return res.status(200).json({
                status: "INVALID",
                message: "Signature Matching failed . Report may have been tampered with."
            });
        }
        const signature = signatureMatch[1].replace(/[^A-Za-z0-p+/=]/g, "").trim();
        console.log(signature);
        const report = text.replace(/BEGIN([\s\S]*?)END/, "").trim();
        const normalizedReport = normalize(report);
        const isValid = verifySignature(normalizedReport, signature);
        if (isValid) {
            await logAction(req.user, "REPORT_VALIDATED", (isValid) ? "VALID" : "INVALID");
            res.status(200).json({
                status: "VALID",
                message: "Signature is valid. Report is authentic and unmodified"
            });
        }
        else {
            await logAction(req.user, "REPORT_VALIDATED", (isValid) ? "VALID" : "INVALID");
            res.status(200).json({
                status: "INVALID",
                message: "Signature verification failed. Report may be tampered."
            });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ err: err.message });
    }
};

exports.getFingerprint = async (req, res) => {
    try {
        const fingerprint = getPublicKeyFingerprint();
        res.json({ fingerprint });
    } catch (err) {
        res.status(500).json({ err: err.message });
    }
    await logAction(req.user, "PUBLIC_KEY_ACCESSED", "public_key");
};

exports.listReports = async (req, res) => {
    try {
        const reports = await VerificationReport.find({}).sort({ verifiedAt: -1 });
        res.json({
            count: reports.length,
            reports
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
};

