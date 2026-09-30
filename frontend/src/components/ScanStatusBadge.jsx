import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const STATUS = {
  queued: { label: "En file", className: "bg-secondary text-secondary-foreground" },
  running: { label: "En cours", className: "bg-warning/15 text-warning" },
  done: { label: "Terminé", className: "bg-success/15 text-success" },
  failed: { label: "Échec", className: "bg-destructive/15 text-destructive" },
};

export function ScanStatusBadge({ status }) {
  const s = STATUS[status] ?? { label: status, className: "" };
  return <Badge variant="outline" className={cn("border-transparent", s.className)}>{s.label}</Badge>;
}

export const isActive = (status) => status === "queued" || status === "running";
