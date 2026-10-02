// Read an image File into a base64 data URI, with client-side type/size checks.
// The server re-validates; this just gives quick feedback.
export const MAX_LOGO_BYTES = 256 * 1024;
export const ALLOWED_LOGO_TYPES = [
  "image/png", "image/jpeg", "image/webp", "image/svg+xml", "image/gif",
];

export function fileToDataUri(file) {
  return new Promise((resolve, reject) => {
    if (!ALLOWED_LOGO_TYPES.includes(file.type)) {
      reject(new Error("Format non supporté (PNG, JPEG, WebP, SVG ou GIF)."));
      return;
    }
    if (file.size > MAX_LOGO_BYTES) {
      reject(new Error(`Image trop lourde (max ${Math.round(MAX_LOGO_BYTES / 1024)} Ko).`));
      return;
    }
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("Lecture du fichier impossible."));
    reader.onload = () => resolve(reader.result);
    reader.readAsDataURL(file);
  });
}
