def pctl(a;p):
  (a | sort) as $s
  | if ($s | length) == 0
    then null
    else $s[(((($s | length) - 1) * p) | floor)]
    end;

def stats(name; arr):
  {
    metric: name,
    n: (arr | length),
    avg: (if (arr | length) > 0 then (arr | add) / (arr | length) else null end),
    p95: pctl(arr; 0.95),
    max: (if (arr | length) > 0 then (arr | max) else null end)
  };

def metric_values(msg; key):
  [
    .[]
    | select(.fields.message == msg)
    | .fields[key]
    | if type == "number" then .
      elif type == "string" then (tonumber?)
      else empty
      end
  ];

{
  generated_from: "timing.ndjson",
  worker: {
    process_ms: stats("process_ms"; metric_values("[crawler] worker timing"; "process_ms")),
    queue_lock_wait_ms: stats("queue_lock_wait_ms"; metric_values("[crawler] worker timing"; "queue_lock_wait_ms")),
    queue_recv_wait_ms: stats("queue_recv_wait_ms"; metric_values("[crawler] worker timing"; "queue_recv_wait_ms")),
    queue_lock_hold_ms: stats("queue_lock_hold_ms"; metric_values("[crawler] worker timing"; "queue_lock_hold_ms")),
    state_lock_wait_ms: stats("state_lock_wait_ms"; metric_values("[crawler] worker timing"; "state_lock_wait_ms")),
    state_lock_hold_ms: stats("state_lock_hold_ms"; metric_values("[crawler] worker timing"; "state_lock_hold_ms")),
    node_total_ms: stats("node_total_ms"; metric_values("[crawler] worker timing"; "node_total_ms"))
  },
  node: {
    connect_ms: stats("connect_ms"; metric_values("[crawler] node timing"; "connect_ms")),
    handshake_ms: stats("handshake_ms"; metric_values("[crawler] node timing"; "handshake_ms")),
    get_addr_ms: stats("get_addr_ms"; metric_values("[crawler] node timing"; "get_addr_ms")),
    process_node_total_ms: stats("process_node_total_ms"; metric_values("[crawler] node timing"; "process_node_total_ms"))
  }
}
