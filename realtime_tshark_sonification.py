#!/usr/bin/env python3
"""
Real-time Tshark traffic analyzer for sonification workflows (Pure Data friendly).

Outputs:
  - normal_stream.txt      (sampled normal traffic context)
  - suspicious_stream.txt  (only suspicious events)

Line format for both files:
  timestamp ip_src ip_dst intensity type
"""

from __future__ import annotations

import argparse
import datetime as _dt
import logging
import shutil
import signal
import subprocess
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, List, Optional, Tuple
from pythonosc import udp_client

IP_PD = "127.0.0.1"
PORT_PD = 9000


@dataclass(frozen=True)
class SensitivityConfig:
    window_seconds: float
    ip_packet_threshold: int
    port_hit_threshold: int
    syn_threshold: int
    spike_multiplier: float
    spike_min_packets_per_sec: int
    normal_sample_ratio: float


SENSITIVITY_PRESETS: Dict[str, SensitivityConfig] = {
    "low": SensitivityConfig(
        window_seconds=30.0,
        ip_packet_threshold=220,
        port_hit_threshold=180,
        syn_threshold=140,
        spike_multiplier=2.8,
        spike_min_packets_per_sec=90,
        normal_sample_ratio=0.08,
    ),
    "medium": SensitivityConfig(
        window_seconds=20.0,
        ip_packet_threshold=140,
        port_hit_threshold=120,
        syn_threshold=90,
        spike_multiplier=2.2,
        spike_min_packets_per_sec=60,
        normal_sample_ratio=0.14,
    ),
    "high": SensitivityConfig(
        window_seconds=12.0,
        ip_packet_threshold=80,
        port_hit_threshold=70,
        syn_threshold=45,
        spike_multiplier=1.7,
        spike_min_packets_per_sec=35,
        normal_sample_ratio=0.20,
    ),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Real-time tshark analyzer with normal+suspicious output streams."
    )
    parser.add_argument("-i", "--interface", required=True, help="Capture interface name")
    parser.add_argument(
        "--sensitivity",
        choices=sorted(SENSITIVITY_PRESETS.keys()),
        default="medium",
        help="Detection sensitivity profile",
    )
    parser.add_argument(
        "--normal-output",
        default="normal_stream.txt",
        help="Path to sampled normal traffic output file",
    )
    parser.add_argument(
        "--suspicious-output",
        default="suspicious_stream.txt",
        help="Path to suspicious events output file",
    )
    parser.add_argument(
        "--history-seconds",
        type=int,
        default=12,
        help="Seconds used to estimate baseline packets/sec for spike detection",
    )
    parser.add_argument(
        "--restart-delay",
        type=float,
        default=2.0,
        help="Delay before restarting tshark after failure/exit",
    )
    parser.add_argument(
        "--timestamp-format",
        choices=["iso", "epoch", "both"],
        default="iso",
        help="Timestamp in outputs: iso=YYYY-MM-DDTHH:MM:SS.mmm, epoch=seconds, both=iso then epoch",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logs")
    return parser.parse_args()


def parse_tcp_port(raw: str) -> str:
    if not raw:
        return "-"
    # tshark may emit "443,80" in some cases.
    token = raw.split(",")[0].strip()
    return token if token else "-"


def parse_tcp_flags(raw: str) -> int:
    if not raw:
        return 0
    text = raw.strip().lower()
    try:
        if text.startswith("0x"):
            return int(text, 16)
        return int(text)
    except ValueError:
        return 0


def is_syn_packet(flags_value: int) -> bool:
    syn_bit = 0x02
    return bool(flags_value & syn_bit)


def clamp_int(value: float, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, int(value)))


def format_ts_iso_local(timestamp: float) -> str:
    # No spaces -> easier tokenizing in Pure Data.
    dt = _dt.datetime.fromtimestamp(timestamp)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{int((timestamp - int(timestamp)) * 1000):03d}"


class RollingTrafficAnalyzer:
    def __init__(self, cfg: SensitivityConfig, history_seconds: int) -> None:
        self.cfg = cfg
        self.window: Deque[Tuple[float, str, str, bool, int]] = deque()
        self.ip_counts: Dict[str, int] = defaultdict(int)
        self.port_counts: Dict[str, int] = defaultdict(int)
        self.syn_count = 0
        self.total_bytes = 0
        self.total_packets = 0
        self.normal_emit_counter = 0

        self.current_sec: Optional[int] = None
        self.current_sec_packets = 0
        self.sec_history: Deque[Tuple[int, int]] = deque(maxlen=max(3, history_seconds))

    def _prune_old(self, now_ts: float) -> None:
        cutoff = now_ts - self.cfg.window_seconds
        while self.window and self.window[0][0] < cutoff:
            old_ts, old_src, old_port, old_syn, old_len = self.window.popleft()
            _ = old_ts  # unused but kept for clarity in tuple semantics
            if old_src != "-":
                self.ip_counts[old_src] -= 1
                if self.ip_counts[old_src] <= 0:
                    self.ip_counts.pop(old_src, None)
            if old_port != "-":
                self.port_counts[old_port] -= 1
                if self.port_counts[old_port] <= 0:
                    self.port_counts.pop(old_port, None)
            if old_syn:
                self.syn_count = max(0, self.syn_count - 1)
            self.total_bytes = max(0, self.total_bytes - old_len)
            self.total_packets = max(0, self.total_packets - 1)

    def _update_spike_buckets(self, packet_ts: float) -> Tuple[float, int]:
        sec = int(packet_ts)
        if self.current_sec is None:
            self.current_sec = sec
            self.current_sec_packets = 0
        elif sec != self.current_sec:
            self.sec_history.append((self.current_sec, self.current_sec_packets))
            self.current_sec = sec
            self.current_sec_packets = 0

        self.current_sec_packets += 1

        if not self.sec_history:
            return 0.0, self.current_sec_packets

        baseline_avg = sum(count for _, count in self.sec_history) / float(len(self.sec_history))
        return baseline_avg, self.current_sec_packets

    def process_packet(
        self, timestamp: float, ip_src: str, ip_dst: str, tcp_flags_raw: str, tcp_port_raw: str, frame_len: int
    ) -> Tuple[bool, str, int]:
        self._prune_old(timestamp)

        port = parse_tcp_port(tcp_port_raw)
        flags_val = parse_tcp_flags(tcp_flags_raw)
        syn = is_syn_packet(flags_val)

        self.window.append((timestamp, ip_src, port, syn, frame_len))
        if ip_src != "-":
            self.ip_counts[ip_src] += 1
        if port != "-":
            self.port_counts[port] += 1
        if syn:
            self.syn_count += 1
        self.total_bytes += frame_len
        self.total_packets += 1

        baseline_pps, current_pps = self._update_spike_buckets(timestamp)
        avg_size = (self.total_bytes / self.total_packets) if self.total_packets else 0.0

        ip_freq = self.ip_counts.get(ip_src, 0) if ip_src != "-" else 0
        port_freq = self.port_counts.get(port, 0) if port != "-" else 0

        reasons: List[str] = []
        if ip_src != "-" and ip_freq >= self.cfg.ip_packet_threshold:
            reasons.append("flood")
        if port != "-" and port_freq >= self.cfg.port_hit_threshold:
            reasons.append("scan")
        if self.syn_count >= self.cfg.syn_threshold:
            reasons.append("syn_flood")

        spike = False
        if baseline_pps > 0:
            if (
                current_pps >= self.cfg.spike_min_packets_per_sec
                and current_pps > baseline_pps * self.cfg.spike_multiplier
            ):
                spike = True
        elif current_pps >= int(self.cfg.spike_min_packets_per_sec * 1.6):
            # Early start fallback when baseline is not yet established.
            spike = True

        if spike:
            reasons.append("spike")

        suspicious = len(reasons) > 0
        event_type = reasons[0] if suspicious else "normal"

        intensity_components = [
            frame_len / 1500.0,
            (ip_freq / max(1, self.cfg.ip_packet_threshold)),
            (port_freq / max(1, self.cfg.port_hit_threshold)),
            (self.syn_count / max(1, self.cfg.syn_threshold)),
            (current_pps / max(1, self.cfg.spike_min_packets_per_sec)),
            (avg_size / 900.0),
        ]
        if suspicious:
            intensity = clamp_int(max(intensity_components) * 100.0, 5, 100)
        else:
            intensity = clamp_int((intensity_components[0] * 0.7 + intensity_components[-1] * 0.3) * 70.0, 1, 70)

        _ = ip_dst  # currently not used for detection but kept for output.
        return suspicious, event_type, intensity

    def should_emit_normal(self) -> bool:
        self.normal_emit_counter += 1
        ratio = self.cfg.normal_sample_ratio
        if ratio <= 0:
            return False
        every_n = max(1, int(round(1.0 / ratio)))
        return self.normal_emit_counter % every_n == 0


def parse_tshark_line(raw_line: str) -> Optional[Tuple[float, str, str, str, str, int]]:
    line = raw_line.strip()
    if not line:
        return None

    fields = line.split("\t")
    if len(fields) < 6:
        fields.extend([""] * (6 - len(fields)))

    ts_text = fields[0].strip()
    if not ts_text:
        return None

    try:
        timestamp = float(ts_text)
    except ValueError:
        return None

    ip_src = fields[1].strip() or "-"
    ip_dst = fields[2].strip() or "-"
    tcp_flags = fields[3].strip() or ""
    tcp_port = fields[4].strip() or "-"

    len_text = fields[5].strip()
    try:
        frame_len = int(len_text) if len_text else 0
    except ValueError:
        frame_len = 0

    return timestamp, ip_src, ip_dst, tcp_flags, tcp_port, frame_len


def build_tshark_command(interface: str) -> List[str]:
    return [
        "tshark",
        "-l",  # line-buffered output
        "-n",  # no DNS/hostname resolution
        "-i",
        interface,
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=f",
        "-e",
        "frame.time_epoch",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
        "-e",
        "tcp.flags",
        "-e",
        "tcp.port",
        "-e",
        "frame.len",
    ]


def run_capture_loop(args: argparse.Namespace) -> int:
    client = udp_client.SimpleUDPClient("127.0.0.1", 9000)


    
    if shutil.which("tshark") is None:
        logging.error("tshark binary was not found in PATH.")
        return 2

    cfg = SENSITIVITY_PRESETS[args.sensitivity]
    analyzer = RollingTrafficAnalyzer(cfg, history_seconds=args.history_seconds)
    command = build_tshark_command(args.interface)
    stop_requested = False

    def _handle_stop(signum: int, frame: object) -> None:
        nonlocal stop_requested
        _ = signum, frame
        stop_requested = True
        logging.info("Stop signal received, shutting down...")

    signal.signal(signal.SIGINT, _handle_stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _handle_stop)

    logging.info("Starting analyzer with sensitivity='%s' on interface='%s'", args.sensitivity, args.interface)
    logging.info("Command: %s", " ".join(command))
    logging.info("Writing normal stream -> %s", args.normal_output)
    logging.info("Writing suspicious stream -> %s", args.suspicious_output)

    with open(args.normal_output, "a", encoding="utf-8", buffering=1) as normal_out, open(
        args.suspicious_output, "a", encoding="utf-8", buffering=1
    ) as suspicious_out:
        while not stop_requested:
            process: Optional[subprocess.Popen[str]] = None
            try:
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                )

                if process.stdout is None:
                    raise RuntimeError("Failed to capture tshark stdout pipe.")

                for raw_line in process.stdout:
                    if stop_requested:
                        break

                    parsed = parse_tshark_line(raw_line)
                    if parsed is None:
                        continue

                    timestamp, ip_src, ip_dst, tcp_flags, tcp_port, frame_len = parsed
                    suspicious, event_type, intensity = analyzer.process_packet(
                        timestamp, ip_src, ip_dst, tcp_flags, tcp_port, frame_len
                    )
                    if args.timestamp_format == "epoch":
                        ts_field = f"{timestamp:.3f}"
                    elif args.timestamp_format == "both":
                        ts_field = f"{format_ts_iso_local(timestamp)} {timestamp:.3f}"
                    else:
                        ts_field = format_ts_iso_local(timestamp)

                    out_line = f"{ts_field} {ip_src} {ip_dst} {intensity} {event_type}\n"

                    if suspicious:
                        suspicious_out.write(out_line)
                    elif analyzer.should_emit_normal():
                        normal_out.write(out_line)

                if stop_requested:
                    break

                stderr_output = ""
                if process.stderr is not None:
                    stderr_output = process.stderr.read().strip()
                return_code = process.wait(timeout=1)
                if return_code != 0:
                    logging.warning("tshark exited with code %s. stderr=%s", return_code, stderr_output or "<empty>")
                else:
                    logging.warning("tshark exited unexpectedly with code 0. Restarting...")

            except Exception as exc:
                logging.exception("Capture loop error: %s", exc)
            finally:
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=1.5)
                    except subprocess.TimeoutExpired:
                        process.kill()

            if not stop_requested:
                time.sleep(max(0.2, float(args.restart_delay)))

    logging.info("Analyzer stopped cleanly.")
    return 0


def main() -> int:
    args = parse_args()
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    return run_capture_loop(args)


if __name__ == "__main__":
    sys.exit(main())
