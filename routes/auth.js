const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const router = express.Router();
const User = require("../models/User");

// REGISTER
router.post("/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    // Email kontrolü
    const existingEmail = await User.findOne({ email });
    if (existingEmail) return res.status(400).json({ error: "Email zaten kayıtlı" });
    
    // Username kontrolü
    const existingUsername = await User.findOne({ username });
    if (existingUsername) return res.status(400).json({ error: "Kullanıcı adı zaten kullanılıyor" });

    const salt = await bcrypt.genSalt(10);
    const hashed = await bcrypt.hash(password, salt);

    const newUser = new User({ 
      username, 
      email, 
      password: hashed 
    });
    await newUser.save();
    
    res.status(201).json({ 
      message: "Kayıt başarılı",
      user: {
        id: newUser._id,
        username: newUser.username,
        email: newUser.email,
        role: newUser.role
      }
    });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ error: "Sunucu hatası" });
  }
});

// LOGIN
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: "Kullanıcı bulunamadı" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: "Hatalı şifre" });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1d",
    });

    res.json({ 
      message: "Giriş başarılı", 
      token,
      role: user.role,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  } catch (err) {
    res.status(500).json({ error: "Sunucu hatası" });
  }
});

// CREATE ADMIN USER (Sadece development için)
router.post("/create-admin", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    // Email kontrolü
    const existingEmail = await User.findOne({ email });
    if (existingEmail) return res.status(400).json({ error: "Email zaten kayıtlı" });
    
    // Username kontrolü
    const existingUsername = await User.findOne({ username });
    if (existingUsername) return res.status(400).json({ error: "Kullanıcı adı zaten kullanılıyor" });

    const salt = await bcrypt.genSalt(10);
    const hashed = await bcrypt.hash(password, salt);

    const newAdmin = new User({ 
      username,
      email, 
      password: hashed,
      role: "admin" 
    });
    await newAdmin.save();
    res.status(201).json({ message: "Admin kullanıcısı oluşturuldu" });
  } catch (err) {
    res.status(500).json({ error: "Sunucu hatası" });
  }
});

module.exports = router;
