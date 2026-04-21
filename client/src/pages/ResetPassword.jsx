import { useState } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import Logo from "../assets/SocialEcho.png";

const ResetPassword = () => {

const { token } = useParams();
const navigate = useNavigate();

const [password, setPassword] = useState("");
const [confirmPassword, setConfirmPassword] = useState("");

const handleSubmit = async (e) => {
  e.preventDefault();
  console.log("token:", token);
  console.log("navigate type:", typeof navigate);
  console.log("fetch type:", typeof fetch);


  if (password !== confirmPassword) {
    alert("Passwords do not match");
    return;
  }

  try {
    const response = await fetch(`https://adaptive-auth-server.onrender.com/auth/reset-password/${token}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ password }),
    });

    const data = await response.json();
    if(response.ok) {
       alert("Password reset successful");
       navigate("/signin");
    } else{
      alert(data.message || "Reset failed");
    }
  }catch (error) {
    console.log("RESET FRONTEND ERROR:", error);
    alert("Password reset failed");
  }
};

return (
<section className="bg-white">
<div className="container mx-auto flex min-h-screen flex-col items-center justify-center px-6">

<form
onSubmit={handleSubmit}
className="w-full max-w-md rounded-xl border bg-white p-8 shadow-lg"
>

<div className="mx-auto flex justify-center">
<img className="h-7 w-auto sm:h-8" src={Logo} alt="SocialEcho" />
</div>

<h2 className="mt-4 text-center text-2xl font-semibold text-gray-800">
Reset Password
</h2>

<div className="relative mt-6 flex items-center">
<input
type="password"
placeholder="New Password"
value={password}
onChange={(e) => setPassword(e.target.value)}
className="block w-full rounded-lg border px-4 py-3"
required
/>
</div>

<div className="relative mt-4 flex items-center">
<input
type="password"
placeholder="Confirm Password"
value={confirmPassword}
onChange={(e) => setConfirmPassword(e.target.value)}
className="block w-full rounded-lg border px-4 py-3"
required
/>
</div>

<div className="mt-6">
<button
type="submit"
className="w-full rounded-lg bg-blue-500 px-6 py-3 text-white hover:bg-blue-700"
>
Reset Password
</button>
</div>

<p className="mt-6 text-center text-sm text-gray-600">
Back to{" "}
<Link
to="/signin"
className="font-medium text-blue-500 hover:underline"
>
Sign In
</Link>
</p>

</form>
</div>
</section>
);
};

export default ResetPassword;