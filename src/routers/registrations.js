const express = require("express");
const router = express.Router();

const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const prisma = require("../utils/prisma.js");

const { createUser } = require("../domains/user.js");

router.post("/", async (req, res) => {
  // Get the username and password from request body
  const { username, password } = req.body;

  // Hash the password: https://github.com/kelektiv/node.bcrypt.js#with-promises
  const hash = await bcrypt.hash(password, 2);

  // Save the user using the prisma user model, setting their password to the hashed version
  const newUser = await createUser(username, hash);

  // Respond back to the client with the created users username and id
  res.status(201).json({ user: newUser });
});

module.exports = router;
