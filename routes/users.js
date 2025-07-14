const express = require("express");
const verifyToken = require("../middleware/auth");
const User = require("../models/User");

const router = express.Router();

// Korumalı kullanıcı bilgisi
router.get("/me", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    if (!user) return res.status(404).json({ error: "Kullanıcı bulunamadı" });
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: "Sunucu hatası" });
  }
});

module.exports = router;
