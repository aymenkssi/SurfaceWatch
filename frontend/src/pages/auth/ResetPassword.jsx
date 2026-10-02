import { useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Loader2 } from "lucide-react";
import { toast } from "sonner";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/context/AuthContext";
import { api, errorMessage } from "@/lib/api";
import { AuthLink } from "./AuthForm";

export default function ResetPassword() {
  const [params] = useSearchParams();
  const token = params.get("token") ?? "";
  const { logout } = useAuth();
  const navigate = useNavigate();
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (password !== confirm) {
      toast.error("Les deux mots de passe ne correspondent pas.");
      return;
    }
    setBusy(true);
    try {
      await api.post("/auth/reset-password", { token, password });
      logout(); // every session opened before the reset is now invalid
      toast.success("Mot de passe modifié. Connectez-vous avec le nouveau.");
      navigate("/login");
    } catch (err) {
      toast.error(errorMessage(err));
      setBusy(false);
    }
  };

  return (
    <div className="flex justify-center pt-8">
      <Card className="w-full max-w-md shadow-soft">
        <CardHeader>
          <CardTitle className="text-2xl">Nouveau mot de passe</CardTitle>
          <CardDescription>Choisissez un nouveau mot de passe pour votre compte.</CardDescription>
        </CardHeader>
        <CardContent>
          {!token ? (
            <Alert variant="destructive">
              <AlertDescription>
                Lien incomplet. Utilisez le lien reçu par e-mail ou faites une nouvelle demande.
              </AlertDescription>
            </Alert>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="password">Nouveau mot de passe</Label>
                <Input id="password" type="password" required minLength={10} maxLength={128}
                       autoComplete="new-password"
                       value={password} onChange={(e) => setPassword(e.target.value)} />
                <p className="text-xs text-muted-foreground">10 caractères minimum.</p>
              </div>
              <div className="space-y-2">
                <Label htmlFor="confirm">Confirmation</Label>
                <Input id="confirm" type="password" required minLength={10} maxLength={128}
                       autoComplete="new-password"
                       value={confirm} onChange={(e) => setConfirm(e.target.value)} />
              </div>
              <Button type="submit" className="w-full" disabled={busy}>
                {busy && <Loader2 className="h-4 w-4 animate-spin" />}
                Enregistrer
              </Button>
            </form>
          )}
          <p className="mt-6 text-sm text-center text-muted-foreground">
            <AuthLink to="/forgot-password">Demander un nouveau lien</AuthLink>
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
