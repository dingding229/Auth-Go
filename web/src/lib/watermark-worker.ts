import {
  scanWatermark,
  type WatermarkWorkerRequest,
  type WatermarkWorkerResponse,
} from "./watermark-scan";

const scope = self as unknown as {
  onmessage: ((event: MessageEvent<WatermarkWorkerRequest>) => void) | null;
  postMessage: (message: WatermarkWorkerResponse) => void;
};
let active: { id: number; controller: AbortController } | undefined;
scope.onmessage = (event) => {
  const message = event.data;
  if (message.type === "cancel") {
    if (active?.id === message.id) active.controller.abort();
    return;
  }
  active?.controller.abort();
  const job = { id: message.id, controller: new AbortController() };
  active = job;
  void scanWatermark(message.file, message.tags, {
    signal: job.controller.signal,
    onProgress: (progress) => {
      if (active === job)
        scope.postMessage({ type: "progress", id: job.id, progress });
    },
  }).then((result) => {
    if (active !== job) return;
    scope.postMessage({ type: "result", id: job.id, result });
    active = undefined;
  });
};
