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
      footer={<>Pas encore de compte ? <AuthLink to="/register">Créer un compte</AuthLink></>}
    />
  );
}
