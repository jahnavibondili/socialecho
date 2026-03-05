const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL,
    pass: process.env.PASSWORD,
  },
});

const sendSecurityAlert = async (userEmail, location, device) => {
  try {
    const mailOptions = {
      from: process.env.EMAIL,
      to: userEmail,
      subject: "⚠️ Suspicious Login Alert",
      html: `
        <h2>Security Alert</h2>
        <p>We detected a suspicious login attempt on your account.</p>

        <p><b>Location:</b> ${location}</p>
        <p><b>Device:</b> ${device}</p>

        <p>If this was not you, please reset your password immediately.</p>
      `,
    };

    await transporter.sendMail(mailOptions);

    console.log("Security alert email sent");
  } catch (error) {
    console.log("Email error:", error);
  }
};
const sendPasswordResetEmail = async (userEmail, resetLink) => {
  try {
    const mailOptions = {
      from: process.env.EMAIL,
      to: userEmail,
      subject: "Reset Your Password",
      html: `
        <h2>Password Reset Request</h2>

        <p>You requested a password reset.</p>

        <a href="${resetLink}">
          Click here to reset your password
        </a>

        <p>This link expires in 15 minutes.</p>

        <p>If you didn't request this, ignore this email.</p>
      `
    };

    await transporter.sendMail(mailOptions);

    console.log("Password reset email sent");

  } catch (error) {
    console.log(error);
  }
};

module.exports = {
  sendSecurityAlert,
  sendPasswordResetEmail
};
