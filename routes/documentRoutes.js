const express = require("express");
const authMiddleware = require("../middleware/authMiddleware");
const permissionMiddleware = require("../middleware/permissionMiddleware");
const PERMISSIONS = require("../config/permissions");
const router = express.Router();
const docupload = require("../config/multer");
const { uploadDocument, listDocuments, getDocument, deleteDocument, transitionDocument, getDocumentHistory } = require("../controllers/documentController");

router.post("/upload", authMiddleware , permissionMiddleware(PERMISSIONS.FILE_UPLOAD), docupload.single("file"), uploadDocument);

router.get("/", authMiddleware , permissionMiddleware(PERMISSIONS.FILE_VIEW), listDocuments);

router.get("/:documentId", authMiddleware, permissionMiddleware(PERMISSIONS.FILE_VIEW), getDocument);

router.delete("/:documentId", authMiddleware , permissionMiddleware(PERMISSIONS.FILE_DELETE), deleteDocument);

router.patch("/:documentId/transition", authMiddleware , transitionDocument);

router.get("/:documentId/history", authMiddleware, permissionMiddleware(PERMISSIONS.FILE_VIEW), getDocumentHistory);

module.exports = router;