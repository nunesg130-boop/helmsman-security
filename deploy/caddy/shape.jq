# Reduces Caddy's live config to the shape of its routes. Keeps structure and
# names only: never header values, tokens, key paths or response bodies.
# Anything it doesn't understand is named, not dropped.
def supported: ["host", "path", "remote_ip", "client_ip", "not"];
def mset:
  with_entries(select(.key | IN("host", "path")))
  + (if .remote_ip then {remote_ip: {ranges: (.remote_ip.ranges // [])}} else {} end)
  + (if .client_ip then {client_ip: {ranges: (.client_ip.ranges // [])}} else {} end)
  + (if .not then {not: [.not[] | mset]} else {} end)
  + {unsupported: [keys[] | select(IN(supported[]) | not)]};
def handler_types: [.. | objects | .handler? // empty] | unique;
def header_names: [.. | objects | select(.handler? == "headers") | ((.request.set // {}), (.request.add // {})) | keys[]] | unique;
def route:
  def handler:
    {handler}
    + (if .upstreams then {upstreams: [.upstreams[]?.dial]} else {} end)
    + (if .rewrite.uri then {rewrite: .rewrite.uri} else {} end)
    + (if .routes then {routes: [.routes[] | route]} else {} end)
    + (if .handle_response then {handleResponse: [.handle_response[] | {
        statusCodes: (.match.status_code // null),
        unsupportedMatch: [(.match // {}) | keys[] | select(. != "status_code")],
        setsStatus: has("status_code"),
        handlers: ((.routes // []) | handler_types),
        setsRequestHeaders: ((.routes // []) | header_names),
        innerMatchers: ([(.routes // [])[] | (.match // [])[] | keys[]] | unique)
      }]} else {} end);
  {group: (.group // null), terminal: (.terminal // false), match: [(.match // [])[] | mset], handle: [(.handle // [])[] | handler]};
{
  version: 2,
  generatedAt: (now | floor),
  servers: [.apps.http.servers // {} | to_entries[] | {
    server: .key,
    listen: .value.listen,
    trustedProxies: (if .value.trusted_proxies then {source: .value.trusted_proxies.source, ranges: (.value.trusted_proxies.ranges // null)} else null end),
    trustedProxiesStrict: ((.value.trusted_proxies_strict // 0) != 0),
    clientIpHeaders: (.value.client_ip_headers // null),
    routes: [.value.routes[]? | route]
  }]
}
