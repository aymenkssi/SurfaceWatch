import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Loader2 } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { errorMessage } from "@/lib/api";

export function AuthForm({ title, description, submitLabel, onSubmit, footer, minLength, passwordHint }) {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setBusy(true);
    try {
      await onSubmit(email, password);
      navigate("/dashboard");
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
          <CardTitle className="text-2xl">{title}</CardTitle>
          <CardDescription>{description}</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email">E-mail</Label>
              <Input id="email" type="email" autoComplete="email" required
                     value={email} onChange={(e) => setEmail(e.target.value)} />
            </div>
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label htmlFor="password">Mot de passe</Label>
                {passwordHint}
              </div>
              <Input id="password" type="password" required minLength={10} maxLength={128}
                     autoComplete={minLength ? "new-password" : "current-password"}
                     value={password} onChange={(e) => setPassword(e.target.value)} />
              {minLength && <p className="text-xs text-muted-foreground">10 caractères minimum.</p>}
            </div>
            <Button type="submit" className="w-full" disabled={busy}>
              {busy && <Loader2 className="h-4 w-4 animate-spin" />}
              {submitLabel}
            </Button>
          </form>
          <p className="mt-6 text-sm text-center text-muted-foreground">{footer}</p>
        </CardContent>
      </Card>
    </div>
  );
}

export const AuthLink = ({ to, children }) => (
  <Link to={to} className="font-medium text-primary hover:underline">{children}</Link>
);
