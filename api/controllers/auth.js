const { hashPassword, comparePassword } = require("../helpers/generic");
const { v4: uuidv4 } = require("uuid");
const jwt = require("jsonwebtoken");
const { User } = require("../models/index");

const { OAuth2Client } = require("google-auth-library");

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// ** Register **
const registerUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    const passwordRegex = new RegExp("^(?=.*[A-Za-z])(?=.*d).{6,}$");
    const emailRegex = new RegExp(
      "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+.[A-Za-z]{2,}$"
    );

    console.log(email, password);

    if (email.length === 0) {
      return res.status(500).send({ message: "Email is required" });
    }

    if (!emailRegex.test(email)) {
      return res.status(500).send({ message: "Email is not valid" });
    }

    if (password.length === 0) {
      return res.status(500).send({ message: "Password is required" });
    }

    if (!passwordRegex.test(password)) {
      return res
        .status(500)
        .send({ message: "Password must include 6 characters and 1 number" });
    }

    const emailExists = await User.findOne({ email });

    if (emailExists) {
      return res.status(500).send({ message: "Email is already taken" });
    }

    const hashedPassword = await hashPassword(password);
    const user = await User.create({
      uuid: uuidv4(),
      email,
      password: hashedPassword,
    });

    const accessToken = jwt.sign(user.toJSON(), process.env.JWT_SECRET);

    return res.status(200).send({
      email: user.email,
      uuid: user.uuid,
      accessToken,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server Error", error });
  }
};

// ** Login **
const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(500).send({ message: "Incorrect email or password" });
    }

    const passwordMatch = await comparePassword(password, user.password);

    if (passwordMatch) {
      const accessToken = jwt.sign(user.toJSON(), process.env.JWT_SECRET);

      res.status(200).send({
        email: user.email,
        uuid: user.uuid,
        accessToken,
      });
    } else {
      return res.status(500).send({ message: "Incorrect email or password" });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server Error", error });
  }
};

// ** Google **
const googleAuth = async (req, res) => {
  const { token } = req.body;

  try {
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();

    const user = {
      googleId: payload.sub,
      email: payload.email,
      name: payload.name,
    };

    const accessToken = jwt.sign(user.toJSON(), process.env.JWT_SECRET);

    res.status(200).send({
      email: user.email,
      uuid: user.uuid,
      accessToken,
    });
  } catch (err) {
    res.status(401).json({ error: "Invalid Google token" });
  }
};

module.exports = {
  registerUser,
  loginUser,
  googleAuth,
};
