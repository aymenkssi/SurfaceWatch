import { Link } from "react-router-dom";
import { useAuth } from "@/context/AuthContext";
import { AuthForm, AuthLink } from "./AuthForm";

export default function Login() {
  const { login } = useAuth();
  return (
    <AuthForm
      title="Connexion"
      description="Accédez à vos domaines et à vos rapports."
      submitLabel="Se connecter"
      onSubmit={login}
      passwordHint={
        <Link to="/forgot-password" className="text-xs text-primary hover:underline">
          Mot de passe oublié ?
        </Link>
      }
      footer={<>Pas encore de compte ? <AuthLink to="/register">Créer un compte</AuthLink></>}
    />
  );
}
