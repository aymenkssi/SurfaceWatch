import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "@/context/AuthContext";
import { api } from "@/lib/api";
import { AuthForm, AuthLink } from "./AuthForm";

export default function Login() {
  const { login } = useAuth();
  const [emailEnabled, setEmailEnabled] = useState(false);

  // "Forgot password" only works when the server has SMTP configured.
  useEffect(() => {
    api.get("/features").then((res) => setEmailEnabled(res.data.email)).catch(() => {});
  }, []);

  return (
    <AuthForm
      title="Connexion"
      description="Accédez à vos domaines et à vos rapports."
      submitLabel="Se connecter"
      onSubmit={login}
      passwordHint={emailEnabled && (
        <Link to="/forgot-password" className="text-xs text-primary hover:underline">
          Mot de passe oublié ?
        </Link>
      )}
      footer={<>Pas encore de compte ? <AuthLink to="/register">Créer un compte</AuthLink></>}
    />
  );
}
