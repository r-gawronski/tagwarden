# Argo CD

Tagwarden works with Argo CD without a plugin. Two snippets for
`argocd-cm` add a **Sync now** button to `ArtifactMirror` resources and
health checks for `ArtifactMirror` and `ClusterMirrorTarget`, so an
application shows a failed sync or a refused mirror as `Degraded`.

## Sync now

The button sets the `tagwarden.dev/sync-now` annotation on the mirror.
Each new value is one request. The controller then:

- starts a sync Job from the mirror's CronJob template (Event
  `SyncRequested`),
- or waits while a Job of the mirror runs, or until
  `limits.minSyncInterval` of the target has passed since the last Job
  started, and starts it then (Event `SyncDeferred`),
- or refuses the request when the mirror is not Ready or is suspended,
  or when the value already named a finished Job (Event `SyncRefused`).

`status.lastSyncRequest` shows the value, the result and when the
controller handled it.

The same works without Argo CD:

```sh
kubectl -n team-a annotate artifactmirror ingress-nginx --overwrite \
  tagwarden.dev/sync-now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

The action loads the `os` module with `require("os")` and sets the
annotation to the current UTC time, for example `2026-11-03T10:00:00Z`.
Two clicks within the same second make one request.

## Health

| Resource | Status | When |
|----------|--------|------|
| ArtifactMirror | Suspended | `spec.suspend` is true |
| ArtifactMirror | Progressing | no `Ready` condition yet, or the controller has not seen the latest spec |
| ArtifactMirror | Degraded | `Ready=False`, message `<reason>: <message>` |
| ArtifactMirror | Progressing | `Ready=True` and no `Synced` condition yet (before the first sync) |
| ArtifactMirror | Degraded | `Synced=False`, message `<reason>: <message>` |
| ArtifactMirror | Healthy | `Ready=True` and `Synced=True`, message is the sync summary |
| ClusterMirrorTarget | Progressing | no `Ready` condition yet |
| ClusterMirrorTarget | Degraded | `Ready=False`, message `<reason>: <message>` |
| ClusterMirrorTarget | Healthy | `Ready=True` |

## Configuration

### Helm values for the argo-cd chart

```yaml
configs:
  cm:
    resource.customizations.actions.mirror.tagwarden.dev_ArtifactMirror: |
      discovery.lua: |
        local actions = {}
        actions["sync-now"] = {
          ["disabled"] = obj.spec ~= nil and obj.spec.suspend == true,
          ["displayName"] = "Sync now",
          ["iconClass"] = "fa fa-fw fa-rotate",
        }
        return actions
      definitions:
      - name: sync-now
        action.lua: |
          local os = require("os")
          if obj.metadata.annotations == nil then
            obj.metadata.annotations = {}
          end
          obj.metadata.annotations["tagwarden.dev/sync-now"] = os.date("!%Y-%m-%dT%H:%M:%SZ")
          return obj
    resource.customizations.health.mirror.tagwarden.dev_ArtifactMirror: |
      local hs = {}
      if obj.spec ~= nil and obj.spec.suspend == true then
        hs.status = "Suspended"
        hs.message = "Mirror is suspended"
        return hs
      end
      local ready, synced
      if obj.status ~= nil and obj.status.conditions ~= nil then
        for _, c in ipairs(obj.status.conditions) do
          if c.type == "Ready" then
            ready = c
          elseif c.type == "Synced" then
            synced = c
          end
        end
      end
      if ready == nil or obj.status.observedGeneration ~= obj.metadata.generation then
        hs.status = "Progressing"
        hs.message = "Waiting for the controller"
        return hs
      end
      if ready.status ~= "True" then
        hs.status = "Degraded"
        hs.message = (ready.reason or "") .. ": " .. (ready.message or "")
        return hs
      end
      if synced == nil then
        hs.status = "Progressing"
        hs.message = "Waiting for the first sync"
        return hs
      end
      if synced.status ~= "True" then
        hs.status = "Degraded"
        hs.message = (synced.reason or "") .. ": " .. (synced.message or "")
        return hs
      end
      hs.status = "Healthy"
      hs.message = synced.message
      return hs
    resource.customizations.health.mirror.tagwarden.dev_ClusterMirrorTarget: |
      local hs = {}
      local ready
      if obj.status ~= nil and obj.status.conditions ~= nil then
        for _, c in ipairs(obj.status.conditions) do
          if c.type == "Ready" then
            ready = c
          end
        end
      end
      if ready == nil then
        hs.status = "Progressing"
        hs.message = "Waiting for the controller"
      elseif ready.status == "True" then
        hs.status = "Healthy"
        hs.message = ready.message
      else
        hs.status = "Degraded"
        hs.message = (ready.reason or "") .. ": " .. (ready.message or "")
      end
      return hs
```

### Raw ConfigMap

Merge these keys into the `argocd-cm` ConfigMap of your Argo CD
installation:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: argocd-cm
  namespace: argocd
data:
  resource.customizations.actions.mirror.tagwarden.dev_ArtifactMirror: |
    discovery.lua: |
      local actions = {}
      actions["sync-now"] = {
        ["disabled"] = obj.spec ~= nil and obj.spec.suspend == true,
        ["displayName"] = "Sync now",
        ["iconClass"] = "fa fa-fw fa-rotate",
      }
      return actions
    definitions:
    - name: sync-now
      action.lua: |
        local os = require("os")
        if obj.metadata.annotations == nil then
          obj.metadata.annotations = {}
        end
        obj.metadata.annotations["tagwarden.dev/sync-now"] = os.date("!%Y-%m-%dT%H:%M:%SZ")
        return obj
  resource.customizations.health.mirror.tagwarden.dev_ArtifactMirror: |
    local hs = {}
    if obj.spec ~= nil and obj.spec.suspend == true then
      hs.status = "Suspended"
      hs.message = "Mirror is suspended"
      return hs
    end
    local ready, synced
    if obj.status ~= nil and obj.status.conditions ~= nil then
      for _, c in ipairs(obj.status.conditions) do
        if c.type == "Ready" then
          ready = c
        elseif c.type == "Synced" then
          synced = c
        end
      end
    end
    if ready == nil or obj.status.observedGeneration ~= obj.metadata.generation then
      hs.status = "Progressing"
      hs.message = "Waiting for the controller"
      return hs
    end
    if ready.status ~= "True" then
      hs.status = "Degraded"
      hs.message = (ready.reason or "") .. ": " .. (ready.message or "")
      return hs
    end
    if synced == nil then
      hs.status = "Progressing"
      hs.message = "Waiting for the first sync"
      return hs
    end
    if synced.status ~= "True" then
      hs.status = "Degraded"
      hs.message = (synced.reason or "") .. ": " .. (synced.message or "")
      return hs
    end
    hs.status = "Healthy"
    hs.message = synced.message
    return hs
  resource.customizations.health.mirror.tagwarden.dev_ClusterMirrorTarget: |
    local hs = {}
    local ready
    if obj.status ~= nil and obj.status.conditions ~= nil then
      for _, c in ipairs(obj.status.conditions) do
        if c.type == "Ready" then
          ready = c
        end
      end
    end
    if ready == nil then
      hs.status = "Progressing"
      hs.message = "Waiting for the controller"
    elseif ready.status == "True" then
      hs.status = "Healthy"
      hs.message = ready.message
    else
      hs.status = "Degraded"
      hs.message = (ready.reason or "") .. ": " .. (ready.message or "")
    end
    return hs
```

## Permissions

Argo CD checks its own RBAC before it runs an action. Allow the action
for the teams that own the mirrors, in `argocd-rbac-cm`:

```csv
p, role:team-a, applications, action/mirror.tagwarden.dev/ArtifactMirror/sync-now, team-a/*, allow
```

In Kubernetes, `patch` on the team's own `ArtifactMirror` objects is
enough to request a sync. A request never changes what the Job does: the
Job comes from the CronJob template and the value only names it.

## Testing the snippets

`argocd admin` runs the scripts against a local file, without a cluster:

```sh
argocd admin settings resource-overrides health mirror.yaml --argocd-cm-path argocd-cm.yaml
argocd admin settings resource-overrides list-actions mirror.yaml --argocd-cm-path argocd-cm.yaml
argocd admin settings resource-overrides run-action mirror.yaml sync-now --argocd-cm-path argocd-cm.yaml
```
