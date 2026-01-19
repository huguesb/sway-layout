sway-layout
===========

Reliably arrange auto-started applications in complex layouts, via sway IPC


What
----

`sway-layout` consumes a json config file that specifies the layout of each
workspace, with possibly nested containers, and the applications to be be
spawned, and whose windows should be positioned in the target containers.


For instance, the following `~/.config/sway/layouts/startup.json`

```json
{
  "workspaces" {
    "1": {"tabbed": ["alacritty -e btop", "alacritty"]},
    "2": {"tabbed": ["firefox"]},
    "3": {"splitv": ["alacritty", "alacritty"]}
  }
}
```

with:

```
exec sway-layout
```
somewhere in your sway config (provided `sway-layout` is in your `PATH`),

would result in workspace 1 having a tabbed layout, with two `alacritty` terminal
instances, the first of which will be running `btop`, while workspace 2 would have
`firefox` windows, in a tabbed layout (if firefox autostarts a previous session
with more than one window), and workspace 3 would have two alacritty windows in a
vertical split.


How
---

This is a pure-Go binary, with no dependencies out of the stdlib. It communicates
with sway via IPC, directly through the Unix Domain Socket instead of spawning
`swaymsg`.

To reliavbly track which command spawns which windows, command invocation goes
through a wrapper process (separate invocation mode of the same binary). The
command line of that wrapper process contains the relevant arrangmeent metadata.

The top-level process processes the configuration, spawns all required applications
through the wrapper, and listens to sway window creation events. It then walks the
process tree to find the wrapper invocation, allowing robust mapping of all windows
to the appropriate destination workspace/container, even in the presence of slow
applications, or applications spwaning multiple windows.

After spawning applications, `sway-layout` waits for a quiet period with no new
windows, and at least one window per spawned application, before it starts
actually re-arranging windows.

For the smoothest UX, new windows are immediately moved to the scratchpad until
all windows are ready to be re-arranged.

