const express = require("express");
const authMiddleware = require("../middleware/authMiddleware");
const permissionMiddleware = require("../middleware/permissionMiddleware");
const PERMISSIONS = require("../config/permissions");
const router = express.Router();
const { createUser, listUsers, getUser, promoteUser, deactivateUser, reactivateUser } = require("../controllers/userController");

router.post("/", authMiddleware , permissionMiddleware(PERMISSIONS.USER_CREATE), createUser);

router.get("/", authMiddleware, permissionMiddleware(PERMISSIONS.USER_LIST), listUsers);

router.get("/:userId", authMiddleware, permissionMiddleware(PERMISSIONS.USER_LIST), getUser);

router.patch("/:userId/role", authMiddleware, permissionMiddleware(PERMISSIONS.USER_PROMOTE), promoteUser);

router.patch("/:userId/deactivate", authMiddleware, permissionMiddleware(PERMISSIONS.USER_DELETE), deactivateUser);

router.patch("/:userId/reactivate", authMiddleware, permissionMiddleware(PERMISSIONS.USER_DELETE), reactivateUser);

module.exports = router;