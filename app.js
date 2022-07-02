require("dotenv").config();
require("./config/database").connect();

const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const auth = require("./middleware/auth");

const app = express();
const user = require("./model/user");

app.use(express.json());

//Login gose here

//Register
app.post("/register", async (req, res) => {
  // our register logic goes here

  try {
    // Get uer input
    const { first_name, last_name, email, password } = req.body;

    // Validate user input
    if (!(email && password && first_name && last_name)) {
      res.status(400).send("All input is required");
    }

    // user alreay exist condition
    // Validate if user exist in our database
    const old = await user.findOne({ email });

    if (old) {
      return res.status(409).send("User already exist. Please Login");
    }

    //Encrypt user password
    const encryptedPassword = await bcrypt.hash(password, 10);

    //Create user in our database
    const data = await user.create({
      first_name,
      last_name,
      email: email.toLowerCase(),
      password: encryptedPassword,
    });

    // Create token
    const token = jwt.sign(
      {
        user_id: data._id,
        email,
      },
      process.env.TOKEN_KEY,
      {
        expiresIn: "2h",
      }
    );

    // Save token
    data.token = token;

    // Return new User
    res.status(201).json(data);
  } catch (error) {
    console.log(error);
  }
});

// Login
app.post("/login", async (req, res) => {
  // our login logic goes here
  try {
    // Get user input
    const { email, password } = req.body;

    // Validate user input
    if (!(email, password)) {
      res.status(400).send("All input is required");
    }

    //Validate if user exist in our database
    const data = await user.findOne({ email });

    if (data && (await bcrypt.compare(password, data.password))) {
      // Create token
      const token = jwt.sign(
        {
          user_id: data._id,
          email,
        },
        process.env.TOKEN_KEY,
        { expiresIn: "2h" }
      );

      data.token = token;

      res.status(200).json(data);
    }

    res.status(400).send("Invalid Credentials");
  } catch (error) {
    console.log(error);
  }
});

app.get("/welcome", auth, (req, res) => {
  res.status(200).send("welcome -/-");
});

module.exports = app;
