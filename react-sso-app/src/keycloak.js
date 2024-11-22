import Keycloak from "keycloak-js";

const keycloak = new Keycloak({
  url: "http://localhost:8080/",
  realm: "demo-sso-realm",
  clientId: "react-app",
});

export default keycloak;
