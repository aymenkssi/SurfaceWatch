import { useEffect, useState } from "react";
import { Loader2, MailCheck } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, errorMessage } from "@/lib/api";
import { AuthLink } from "./AuthForm";

export default function ForgotPassword() {
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);
  const [emailEnabled, setEmailEnabled] = useState(true);

  useEffect(() => {
    api.get("/features").then((res) => setEmailEnabled(res.data.email)).catch(() => {});
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setBusy(true);
    try {
      await api.post("/auth/forgot-password", { email });
      setSent(true);
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex justify-center pt-8">
      <Card className="w-full max-w-md shadow-soft">
        <CardHeader>
          <CardTitle className="text-2xl">Mot de passe oublié</CardTitle>
          <CardDescription>
            Indiquez l'e-mail de votre compte : nous vous enverrons un lien de réinitialisation.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {!emailEnabled ? (
            <Alert variant="destructive">
              <AlertDescription>
                L'envoi d'e-mails n'est pas encore activé sur ce serveur : la réinitialisation par
                e-mail est indisponible pour le moment. Contactez l'administrateur.
              </AlertDescription>
            </Alert>
          ) : sent ? (
            <div className="flex gap-3 text-sm">
              <MailCheck className="h-5 w-5 text-primary shrink-0" />
              <p>
                Si un compte existe pour <strong>{email}</strong>, un e-mail vient de lui être
                envoyé. Le lien est valable une heure et ne fonctionne qu'une fois.
              </p>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="email">E-mail</Label>
                <Input id="email" type="email" autoComplete="email" required
                       value={email} onChange={(e) => setEmail(e.target.value)} />
              </div>
              <Button type="submit" className="w-full" disabled={busy}>
                {busy && <Loader2 className="h-4 w-4 animate-spin" />}
                Envoyer le lien
              </Button>
            </form>
          )}
          <p className="mt-6 text-sm text-center text-muted-foreground">
            <AuthLink to="/login">Retour à la connexion</AuthLink>
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
