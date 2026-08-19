const matches = workspace.stackingOrder.filter(
    (window) => window.pid === __KONSOLE_OWNER_PID__ && window.normalWindow,
);

if (matches.length === 1) {
    matches[0].minimized = false;
    workspace.activeWindow = matches[0];
    workspace.raiseWindow(matches[0]);
}
