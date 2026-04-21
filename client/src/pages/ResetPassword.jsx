import { useState } from "react";
import axios from "axios";
import { useParams } from "react-router-dom";

export default function ResetPassword() {
  const { token } = useParams();
  const [password, setPassword] = useState("");

  const handleReset = async () => {
    await axios.post(`/auth/reset-password/${token}`, { password });
    alert("Password reset successful");
  };

  return (
    <div>
      <h2>Reset Password</h2>
      <input
        type="password"
        placeholder="New password"
        onChange={(e) => setPassword(e.target.value)}
      />
      <button onClick={handleReset}>Reset</button>
    </div>
  );
}