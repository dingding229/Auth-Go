export function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename.replace(/[\\/\r\n]/g, "_");
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
