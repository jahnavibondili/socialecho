import { useState } from "react";
import { Link } from "react-router-dom";
import Logo from "../assets/SocialEcho.png";

const ForgotPassword = () => {

const [email, setEmail] = useState("");
const [message, setMessage] = useState("");
const [error, setError] = useState("");

const handleSubmit = async (e) => {
  e.preventDefault();
  console.log("Button Clicked");

  try {
    const response = await fetch("https://adaptive-auth-server.onrender.com/auth/forgot-password", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ email }),
    });

    console.log("Response received");

    const data = await response.json();

    if (response.ok) {
      setMessage("Reset link sent to your email successfully.");
      setError("");
    } else {
      setError(data.message || "Something went wrong");
      setMessage("");
    }

  } catch (error) {
    console.log("ERROR:", error);
    setError("Server error. Please try again.");
    setMessage("");
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
Forgot Password
</h2>

<div className="relative mt-6 flex items-center">
<input
type="email"
placeholder="Enter email"
value={email}
onChange={(e) => setEmail(e.target.value)}
className="block w-full rounded-lg border px-4 py-3"
required
/>
</div>

<div className="mt-6">
<button
type="submit"
className="w-full rounded-lg bg-blue-500 px-6 py-3 text-white hover:bg-blue-700"
>
Send Reset Link
</button>
</div>

{message && (
  <div className="mt-4 rounded-lg bg-green-100 border border-green-400 text-green-700 px-4 py-3 text-center">
    {message}
  </div>
)}

{error && (
  <div className="mt-4 rounded-lg bg-red-100 border border-red-400 text-red-700 px-4 py-3 text-center">
    {error}
  </div>
)}

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

export default ForgotPassword;