import { useAuth } from "@/context/AuthContext";
import { AuthForm, AuthLink } from "./AuthForm";

export default function Register() {
  const { register } = useAuth();
  return (
    <AuthForm
      title="Créer un compte"
      description="Gratuit. Seuls votre e-mail et vos domaines sont conservés."
      submitLabel="Créer mon compte"
      onSubmit={register}
      minLength
      footer={<>Déjà inscrit ? <AuthLink to="/login">Se connecter</AuthLink></>}
    />
  );
}
