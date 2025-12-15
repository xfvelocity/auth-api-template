const {
  hashPassword,
  comparePassword,
  sendEmailVerification,
} = require("../helpers/generic");
const { v4: uuidv4 } = require("uuid");
const jwt = require("jsonwebtoken");
const { User, EmailValidation } = require("../models/index");

const { OAuth2Client } = require("google-auth-library");

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// ** Register **
const registerUser = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const passwordRegex = new RegExp("^(?=.*[A-Za-z])(?=.*d).{6,}$");
    const emailRegex = new RegExp(
      "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+.[A-Za-z]{2,}$"
    );

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
      name,
      email,
      password: hashedPassword,
    });

    await sendEmailVerification(user);

    return res.status(200).send({
      uuid: user.uuid,
      emailVerified: false,
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
      let userObject = {
        uuid: user.uuid,
        emailVerified: user.emailVerified,
      };

      if (user.emailVerified) {
        const accessToken = jwt.sign(user.toJSON(), process.env.JWT_SECRET);

        userObject = {
          ...userObject,
          name: user.name,
          email: user.email,
          googleId: user.googleId,
          accessToken,
        };
      } else {
        await sendEmailVerification(user);
      }

      res.status(200).send(userObject);

      return userObject;
    } else {
      return res.status(500).send({ message: "Incorrect email or password" });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server Error", error });
  }
};

// ** Verify code **
const verifyCode = async (req, res) => {
  try {
    const { uuid, code } = req.body;

    const emailVerification = await EmailValidation.findOne({ uuid });

    if (!emailVerification) {
      return res.status(400).send({ message: "Code has expired" });
    }

    if (emailVerification.code === parseInt(code)) {
      const user = await User.findOne({ uuid });

      await User.findByIdAndUpdate(user._id, { emailVerified: true });
      await EmailValidation.findByIdAndDelete(emailVerification._id);

      const accessToken = jwt.sign(user.toJSON(), process.env.JWT_SECRET);

      res.status(200).send({
        name: user.name,
        email: user.email,
        uuid: user.uuid,
        emailVerified: true,
        accessToken,
      });
    } else {
      return res.status(400).send({ message: "Invalid code" });
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

    let user = await User.findOne({ googleId: payload.sub });

    if (!user) {
      const newUser = await User.create({
        uuid: uuidv4(),
        name: payload.name,
        email: payload.email,
        emailVerified: payload.email_verified,
        googleId: payload.sub,
        password: null,
      });

      if (!payload.email_verified) {
        await sendEmailVerification(newUser);

        return res.status(200).send({
          uuid: user.uuid,
          emailVerified: false,
        });
      }

      user = newUser;
    }

    const accessToken = jwt.sign(user.toJSON(), process.env.JWT_SECRET);

    return res.status(200).send({
      name: user.name,
      email: user.email,
      uuid: user.uuid,
      emailVerified: user.emailVerified,
      googleId: user.googleId,
      accessToken,
    });
  } catch (err) {
    console.error(err);
    res.status(401).json({ message: "Invalid Google token", error: err });
  }
};

module.exports = {
  registerUser,
  loginUser,
  googleAuth,
  verifyCode,
};
