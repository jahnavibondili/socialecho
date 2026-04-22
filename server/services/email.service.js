const nodemailer = require("nodemailer");

const sendPasswordResetEmail = async (userEmail, resetLink) => {
  console.log("🔥 Email function triggered");
  try {
    console.log("📧 Sending email using Gmail SMTP...");

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL,
        pass: process.env.APP_PASSWORD, // NOT your normal password
      },
    });

    const mailOptions = {
      from: `"SocialEcho" <${process.env.EMAIL}>`,
      to: process.env.EMAIL,
      subject: "Reset Your Password",
      html: `
        <h2>Password Reset</h2>
        <p>Click below to reset your password:</p>
        <a href="${resetLink}">${resetLink}</a>
        <p>This link expires in 10 minutes.</p>
      `,
    };

    const info = await transporter.sendMail(mailOptions);

    console.log("✅ Email sent:", info.response);

  } catch (error) {
    console.log("❌ Email ERROR:");
    console.log(error);
    throw error;
  }
};

module.exports = { sendPasswordResetEmail };