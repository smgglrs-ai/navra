# navra-ui — Headless/Remote Admin Console

navra-ui is a React web app served by `navra-server` for managing navra
remotely. It is designed for **headless server and SSH environments** where
no desktop app is available nearby.

Use navra-ui to manage agents, flows, permissions, audit trails, and safety
configuration over a browser connection to a remote navra daemon.

## Desktop users

If you are running navra on a local desktop and using ai-workbench to build
or deploy AI models, the **ai-workbench Governance screen**
(`github.com/fabiendupont/ai-workbench`) provides the same governance surface
integrated with the model lifecycle tooling. You do not need navra-ui in that
workflow.

## Development

```bash
cd navra-ui
npm install
npm run dev        # dev server with HMR
npm run build      # production build (output: dist/)
```

The production build is embedded into `navra-server` and served at `/ui/`.
