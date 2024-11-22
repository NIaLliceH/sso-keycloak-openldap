import React from "react";
import { ReactKeycloakProvider } from "@react-keycloak/web";
import keycloak from "./keycloak";
import Profile from "./Profile";

function App() {
  return (
    <ReactKeycloakProvider authClient={keycloak}>
      <Profile />
    </ReactKeycloakProvider>
  );
}

export default App;
