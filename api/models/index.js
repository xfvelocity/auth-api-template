const mongoose = require("mongoose");
const Schema = mongoose.Schema;

// ** User **
const userSchema = new Schema({
  googleId: {
    type: String,
    default: null,
  },
  uuid: String,
  email: {
    type: String,
    unique: true,
  },
  password: String,
  emailVerified: Boolean,
});

const UserModel = mongoose.model("User", userSchema);

// ** Email Verification **
const emailValidationSchema = new Schema({
  uuid: String,
  code: Number,
  createdAt: {
    type: Date,
    default: Date.now(),
    expires: "15m",
  },
});

const EmailValidationModel = mongoose.model(
  "EmailValidation",
  emailValidationSchema
);

module.exports = {
  User: UserModel,
  EmailValidation: EmailValidationModel,
};
