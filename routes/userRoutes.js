const express = require("express");
const authMiddleware = require("../middleware/authMiddleware");
const permissionMiddleware = require("../middleware/permissionMiddleware");
const PERMISSIONS = require("../config/permissions");
const User = require("../models/User");
const Role = require("../models/Role");
const router = express.Router();
const bcrypt = require("bcrypt");
const { logAction } = require("../services/auditService");
const { createUser } = require("../controllers/userController");

router.post("/", authMiddleware , permissionMiddleware(PERMISSIONS.USER_CREATE), createUser);

router.get("/", authMiddleware, permissionMiddleware(PERMISSIONS.USER_LIST), async (req, res) => {
    try {
        const users = await User.find().populate("role").select("-passwordHash");
        console.log(users);
        const formatted = users.map(user => ({
            userId: user.userId,
            username: user.username,
            email: user.email,
            role: user.role.roleName,
            isActive: user.isActive,
            createdAt: user.createdAt
        }));
        await logAction(req.user, "USER_LIST", "user");
        return res.json({
            count: formatted.length,
            users: formatted
        });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: err.message });
    }
});

router.get("/:userId", authMiddleware, permissionMiddleware(PERMISSIONS.USER_LIST), async (req, res) => {
    try {
        const { userId } = req.params;
        const user = await User.findOne({ userId }).populate("role").select("-passwordHash");
        if (!user) return res.status(404).json({ message: "User not found" });
        await logAction(req.user, "USER_VIEW", "user");
        return res.json({
            user: {
                userId: user.userId,
                username: user.username,
                email: user.email,
                role: user.role.roleName,
                isActive: user.isActive,
                createdAt: user.createdAt
            }
        });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: err.message });
    }
});

router.patch("/:userId/role", authMiddleware, permissionMiddleware(PERMISSIONS.USER_PROMOTE), async (req, res) => {
    try {
        const { userId } = req.params;
        console.log(userId);
        const { roleName } = req.body;
        if (!roleName) {
            return res.status(400).json({ message: "rolename is required" });
        }
        const targetUser = await User.findOne({ userId });
        if (!targetUser) {
            return res.status(404).json({ message: "User not found" });
        }
        const newRole = await Role.findOne({ roleName: roleName.toUpperCase() });
        if (!newRole) {
            return res.status(400).json({ message: "Role not found" });
        }
        if (req.user.userId === targetUser.userId) {
            return res.status(400).json({ message: "Cannot modify your own role" });
        }
        targetUser.role = newRole._id;
        await targetUser.save();
        await logAction(req.user, "USER_PROMOTION", "user");
        return res.status(200).json({
            message: "User role updated successfully",
            updateUserId: targetUser.userId,
            newRole: newRole.roleName
        });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: "Server error" });
    }
});

router.patch("/:userId/deactivate", authMiddleware, permissionMiddleware(PERMISSIONS.USER_DELETE), async (req, res) => {
    try {
        const { userId } = req.params;
        const targetUser = await User.findOne({ userId });
        if (!targetUser) {
            return res.status(404).json({ message: "User not found" });
        }
        if (req.user.userId === targetUser.userId) {
            return res.status(400).json({ message: "Cannot deactivate own account" });
        }
        if (!targetUser.isActive) {
            return res.status(400).json({ message: "User already deactivated" });
        }
        targetUser.isActive = false;
        await targetUser.save();
        await logAction(req.user, "USER_DEACTIVATION", "user");
        return res.json({
            message: "User deactivated successfully",
            userId: targetUser.userId
        });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: err.message });
    }
});

router.patch("/:userId/reactivate", authMiddleware, permissionMiddleware(PERMISSIONS.USER_DELETE), async (req, res) => {
    try {
        const { userId } = req.params;
        const targetUser = await User.findOne({ userId });
        if (!targetUser) {
            return res.status(404).json({ message: "User Not Found" });
        }
        if (targetUser.isActive) {
            return res.status(400).json({ message: "User is already active" });
        }
        targetUser.isActive = true;
        await targetUser.save();
        await logAction(req.user, "USER_REACTIVATION", "user");
        res.status(200).json({ message: "User reactivated", userId: targetUser.userId });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: err.message });
    }
});

module.exports = router;