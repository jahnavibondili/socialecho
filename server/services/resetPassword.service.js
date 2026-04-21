const crypto = require("crypto");
const User = require("../models/user.model");

const generateResetToken = () => {
  return crypto.randomBytes(32).toString("hex");
};

const setResetToken = async (email) => {
  const token = generateResetToken();

  const user = await User.findOne({ email });

  if (!user) return null;

  user.resetPasswordToken = token;
  user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

  await user.save();

  return token;
};

module.exports = { setResetToken };