const { google } = require("googleapis");

const sendPasswordResetEmail = async (userEmail, resetLink) => {
  try {
    console.log("📧 Gmail API function called");

    const oauth2Client = new google.auth.OAuth2(
      process.env.CLIENT_ID,
      process.env.CLIENT_SECRET,
      "https://developers.google.com/oauthplayground"
    );

    oauth2Client.setCredentials({
      refresh_token: process.env.REFRESH_TOKEN,
    });

    const gmail = google.gmail({ version: "v1", auth: oauth2Client });

    const message = [
     `From: "SocialEcho" <${process.env.EMAIL}>`,
     `To: ${userEmail}`,
     `Subject: Reset Your Password`,
     `MIME-Version: 1.0`,
      `Content-Type: text/html; charset=UTF-8`,
      "",
     `<h2>Password Reset</h2>
      <p>Click the link below to reset your password:</p>
     <a href="${resetLink}">${resetLink}</a>
     <p>This link expires in 10 minutes.</p>`
    ].join("\r\n");

    const encodedMessage = Buffer.from(message)
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");

    await gmail.users.messages.send({
      userId: "me",
      requestBody: {
        raw: encodedMessage,
      },
    });

    console.log("✅ Email sent via Gmail API");

  } catch (error) {
      console.log("❌ Gmail API ERROR:");
      console.log(JSON.stringify(error, null, 2));
}
};

module.exports = { sendPasswordResetEmail };