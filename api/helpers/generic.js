const bcrupt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { EmailValidation } = require("../models/index");

const { MailtrapClient } = require("mailtrap");

// ** Auth **
const hashPassword = (password) => {
  return new Promise((resolve, reject) => {
    bcrupt.genSalt(12, (err, salt) => {
      if (err) {
        reject(err);
      }

      bcrupt.hash(password, salt, (err, hash) => {
        if (err) {
          reject(err);
        }

        resolve(hash);
      });
    });
  });
};

const comparePassword = (password, hashedPassword) => {
  return bcrupt.compare(password, hashedPassword);
};

const authenticateToken = (req, res, next) => {
  const token = req.header("Authorization");

  if (!token) {
    return res.status(401).json({ message: "Access denied. Token missing." });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ message: "Access denied. Invalid token." });
  }
};

// ** Paginated list **
const paginatedList = async (req, model, query, sortBy = {}) => {
  const page = parseInt(req.query.page || "") || 1;
  const perPage = parseInt(req.query.perPage || "") || 10;

  const pageItems = await model
    .find(query)
    .sort(sortBy)
    .skip((page - 1) * perPage)
    .limit(perPage)
    .lean();
  const total = await model.countDocuments(query);

  return {
    data: pageItems,
    meta: {
      page,
      perPage,
      totalPages: Math.ceil(total / perPage),
      total,
    },
  };
};

const sendEmailVerification = async (user) => {
  const client = new MailtrapClient({
    endpoint: process.env.MAILTRAP_ENDPOINT,
    token: process.env.MAILTRAP_TOKEN,
  });

  const emailVerificationCode = Math.floor(10000 + Math.random() * 90000);

  await client.send({
    from: {
      name: "Email Token",
      email: process.env.MAILTRAP_FROM_EMAIL,
    },
    to: [
      {
        email: user.email,
      },
    ],
    template_uuid: process.env.MAILTRAP_TEMPLATE,
    template_variables: {
      user_email: user.email,
      code: emailVerificationCode,
    },
  });

  const expiryDate = new Date();

  expiryDate.setMinutes(expiryDate.getMinutes() + 15);

  await EmailValidation.create({
    uuid: user.uuid,
    code: emailVerificationCode,
    expiresAt: expiryDate,
  });
};

module.exports = {
  paginatedList,
  hashPassword,
  comparePassword,
  authenticateToken,
  sendEmailVerification,
};
