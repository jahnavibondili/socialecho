import { useState } from "react";
import axios from "axios";

export default function ForgotPassword() {
  const [email, setEmail] = useState("");

  const handleSubmit = async () => {
    await axios.post("/auth/forgot-password", { email });
    alert("Reset link sent to email");
  };

  return (
    <div>
      <h2>Forgot Password</h2>
      <input
        type="email"
        placeholder="Enter email"
        onChange={(e) => setEmail(e.target.value)}
      />
      <button onClick={handleSubmit}>Send Link</button>
    </div>
  );
}