import React, { useState } from "react";
import {
  startRegistration,
  startAuthentication,
} from "@simplewebauthn/browser";

const WebAuthn = () => {
  const [userId, setUserId] = useState("user123");
  const [username, setUsername] = useState("Usuário");
  const [message, setMessage] = useState("");

  const log = (msg: string, data?: any) => {
    console.log(`🔍 [WebAuthn] ${msg}`, data);
  };

  const register = async () => {
    try {
      log("Starting registration process...");

      // Request registration challenge from the server
      log("Fetching registration challenge...");
      const res = await fetch(
        "http://localhost:3000/api/webauthn/register-challenge",
        {
          method: "POST",
          body: JSON.stringify({ userId, username }),
          headers: { "Content-Type": "application/json" },
        }
      );

      if (!res.ok) {
        throw new Error(`Server error: ${res.statusText}`);
      }

      const { options } = await res.json();
      log("Received registration challenge", options);

      // Start WebAuthn registration in the browser
      log("Starting WebAuthn registration...");
      const credential = await startRegistration(options);
      log("WebAuthn registration completed", credential);

      // Send the credential to the server
      log("Sending registration data to server...");
      const verifyRes = await fetch(
        "http://localhost:3000/api/webauthn/register",
        {
          method: "POST",
          body: JSON.stringify({ userId, credential }),
          headers: { "Content-Type": "application/json" },
        }
      );

      if (!verifyRes.ok) {
        throw new Error(`Server error: ${verifyRes.statusText}`);
      }

      const { success } = await verifyRes.json();
      if (success) {
        log("Registration successful! ✅");
        setMessage("Registration completed! 🚀");
      } else {
        throw new Error("Registration failed");
      }
    } catch (error) {
      log("Error during registration", error);
      setMessage(`Registration error: ${error}`);
    }
  };

  const authenticate = async () => {
    try {
      log("Starting authentication process...");

      // Request authentication challenge from the server
      log("Fetching authentication challenge...");
      const res = await fetch(
        "http://localhost:3000/api/webauthn/authenticate-challenge",
        {
          method: "POST",
          body: JSON.stringify({ userId }),
          headers: { "Content-Type": "application/json" },
        }
      );

      if (!res.ok) {
        throw new Error(`Server error: ${res.statusText}`);
      }

      const { options } = await res.json();
      log("Received authentication challenge", options);

      // Start WebAuthn authentication in the browser
      log("Starting WebAuthn authentication...");
      const assertion = await startAuthentication(options);
      log("WebAuthn authentication completed", assertion);

      // Send the assertion to the server
      log("Sending authentication data to server...");
      const verifyRes = await fetch(
        "http://localhost:3000/api/webauthn/authenticate",
        {
          method: "POST",
          body: JSON.stringify({ userId, assertion }),
          headers: { "Content-Type": "application/json" },
        }
      );

      if (!verifyRes.ok) {
        throw new Error(`Server error: ${verifyRes.statusText}`);
      }

      const { success } = await verifyRes.json();
      if (success) {
        log("Authentication successful! ✅");
        setMessage("Authenticated successfully! ✅");
      } else {
        throw new Error("Authentication failed");
      }
    } catch (error) {
      log("Error during authentication", error);
      setMessage(`Authentication error: ${error}`);
    }
  };

  return (
    <div>
      <h1>WebAuthn Passkey</h1>
      <input
        type="text"
        placeholder="User ID"
        value={userId}
        onChange={(e) => setUserId(e.target.value)}
      />
      <button onClick={register}>Register Passkey 🔑</button>
      <button onClick={authenticate}>Authenticate ✅</button>
      <p>{message}</p>
    </div>
  );
};

export default WebAuthn;
