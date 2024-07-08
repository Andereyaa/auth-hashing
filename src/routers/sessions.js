const express = require("express");
const router = express.Router();

const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const prisma = require("../utils/prisma.js");

const { getUserByUsername } = require("../domains/user.js");

const secret = process.env.JWT_SECRET;

router.post("/", async (req, res) => {
  const { username, password } = req.body;
  // Get the username and password from the request body

  // Check that a user with that username exists in the database
  // Use bcrypt to check that the provided password matches the hashed password on the user
  // If either of these checks fail, respond with a 401 "Invalid username or password" error
  const found = await getUserByUsername(username);
  if (!found) {
    res.status(404).json({ error: "username does not exist" });
    return;
  }

  const match = bcrypt.compareSync(password, found.password);
  if (!match) {
    res.status(401).json({ error: "wrong password" });
    return;
  }

  // If the user exists and the passwords match, create a JWT containing the username in the payload
  // Use the JWT_SECRET environment variable for the secret key
  let token = jwt.sign(username, secret);

  // Send a JSON object with a "token" key back to the client, the value is the JWT created
  res.status(201).json({ token: token });
});

module.exports = router;
