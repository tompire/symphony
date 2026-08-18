defmodule SymphonyElixir.Reliability do
  @moduledoc """
  Durable operator alerts and Langfuse lifecycle traces for unattended runs.
  """

  require Logger

  @secret_key_re ~r/(authorization|api[_-]?key|secret|token|password|credential|cookie|session)/i

  def alert(kind, attrs) when is_binary(kind) and is_map(attrs) do
    event = %{
      "eventType" => "symphony_#{kind}",
      "eventId" => Base.encode16(:crypto.strong_rand_bytes(32), case: :lower),
      "createdAt" => DateTime.utc_now() |> DateTime.to_iso8601(),
      "issue" => attrs[:identifier] || attrs["identifier"],
      "state" => attrs[:state] || attrs["state"],
      "kind" => kind,
      "title" => attrs[:title] || attrs["title"],
      "url" => attrs[:issue_url] || attrs["issue_url"],
      "message" => attrs[:error] || attrs["error"] || kind,
      "data" => sanitize(attrs)
    }

    Task.Supervisor.start_child(SymphonyElixir.TaskSupervisor, fn ->
      post_alert(event)
      emit_trace(event)
    end)

    :ok
  rescue
    error ->
      Logger.error("Reliability alert failed: #{Exception.message(error)}")
      :ok
  end

  defp post_alert(event) do
    case System.get_env("SYMPHONY_ALERT_WEBHOOK_URL") do
      nil ->
        :ok

      "" ->
        :ok

      url ->
        headers =
          case env("SYMPHONY_ALERT_WEBHOOK_TOKEN") || env("CODEX_NEEDS_INPUT_BRIDGE_TOKEN") do
            nil -> []
            token -> [{"authorization", "Bearer #{token}"}]
          end

        case Req.post(url, json: event, headers: headers, receive_timeout: 10_000) do
          {:ok, %{status: status}} when status in 200..299 -> :ok
          {:ok, response} -> Logger.error("Reliability alert webhook returned #{response.status}")
          {:error, reason} -> Logger.error("Reliability alert webhook failed: #{inspect(reason)}")
        end
    end
  end

  defp emit_trace(event) do
    with public when is_binary(public) <- env("LANGFUSE_PUBLIC_KEY"),
         secret when is_binary(secret) <- env("LANGFUSE_SECRET_KEY") do
      trace_id = event["eventId"]

      payload = %{
        batch: [
          %{
            id: "trace-#{trace_id}",
            timestamp: event["createdAt"],
            type: "trace-create",
            body: %{
              id: trace_id,
              name: "symphony.#{event["kind"]}",
              userId: "symphony",
              sessionId: event["issue"] || trace_id,
              input: sanitize(event["data"]),
              metadata: %{source: "symphony", issue: event["issue"], kind: event["kind"]},
              tags: ["symphony", event["kind"]]
            }
          },
          %{id: "event-#{trace_id}", timestamp: event["createdAt"], type: "event-create", body: %{id: "event-#{trace_id}", traceId: trace_id, name: event["kind"], input: sanitize(event)}}
        ]
      }

      base = env("LANGFUSE_BASE_URL") || "https://cloud.langfuse.com"

      case Req.post("#{String.trim_trailing(base, "/")}/api/public/ingestion", auth: {:basic, "#{public}:#{secret}"}, json: payload, receive_timeout: 10_000) do
        {:ok, %{status: status}} when status in 200..299 -> :ok
        {:ok, response} -> Logger.error("Langfuse reliability trace returned #{response.status}")
        {:error, reason} -> Logger.error("Langfuse reliability trace failed: #{inspect(reason)}")
      end
    else
      _ -> :ok
    end
  end

  defp env(name) do
    case System.get_env(name) do
      nil -> nil
      value -> String.trim(value)
    end
  end

  defp sanitize(value) when is_map(value) do
    value
    |> Enum.map(fn {key, child} -> {key, if(Regex.match?(@secret_key_re, to_string(key)), do: "[redacted]", else: sanitize(child))} end)
    |> Map.new()
  end

  defp sanitize(value) when is_list(value), do: Enum.map(value, &sanitize/1)
  defp sanitize(value) when is_binary(value), do: String.slice(value, 0, 1200)
  defp sanitize(value), do: value
end
