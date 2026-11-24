"""On-site camera monitoring with OpenCV: motion, person and restricted-zone detection.

Privacy by design:

* video never leaves this machine — only detections (type, zone, confidence, count) are sent;
* there is no face or identity recognition: the person detector (OpenCV HOG) only says "a person
  shape is here";
* a still snapshot is sent only while the console has privacy mode *off* for this camera, and
  people in it are blurred first unless the console turned blurring off;
* the camera source (index or RTSP URL, which may contain a password) stays local.

Detection is driven by the camera's settings in the console (fetched from the server): nothing is
analysed while detection is off. Install with ``pip install "sentinel-x-agent[vision]"``.
"""

from __future__ import annotations

import base64
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

try:  # optional dependency
    import cv2
    import numpy as np
except ImportError:  # pragma: no cover - exercised only without the extra installed
    cv2 = None
    np = None

log = logging.getLogger("sentinel.vision")


def require_opencv() -> None:
    if cv2 is None:
        raise RuntimeError('OpenCV is not installed: pip install "sentinel-x-agent[vision]"')


@dataclass(frozen=True)
class Box:
    x: int
    y: int
    w: int
    h: int

    @property
    def area(self) -> int:
        return self.w * self.h


@dataclass
class Detection:
    type: str  # motion | person | zone_intrusion
    zone: str | None = None
    confidence: float | None = None
    objects: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if v is not None}


class MotionDetector:
    """Background subtraction (MOG2); ignores the first frames while the model learns the scene."""

    def __init__(self, min_area_ratio: float = 0.004, warmup_frames: int = 5) -> None:
        require_opencv()
        self.subtractor = cv2.createBackgroundSubtractorMOG2(
            history=200, varThreshold=25, detectShadows=False
        )
        self.min_area_ratio = min_area_ratio
        self.warmup_frames = warmup_frames
        self.frames = 0

    def detect(self, frame: Any) -> list[Box]:
        self.frames += 1
        gray = cv2.GaussianBlur(cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY), (5, 5), 0)
        mask = self.subtractor.apply(gray)
        if self.frames <= self.warmup_frames:
            return []
        _, mask = cv2.threshold(mask, 127, 255, cv2.THRESH_BINARY)
        mask = cv2.dilate(mask, None, iterations=2)
        contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        minimum = self.min_area_ratio * frame.shape[0] * frame.shape[1]
        return [Box(*cv2.boundingRect(c)) for c in contours if cv2.contourArea(c) >= minimum]


class PersonDetector:
    """OpenCV's built-in HOG people detector: shape only, never identity."""

    def __init__(self, min_weight: float = 0.5, max_width: int = 640) -> None:
        require_opencv()
        self.hog = cv2.HOGDescriptor()
        self.hog.setSVMDetector(cv2.HOGDescriptor_getDefaultPeopleDetector())
        self.min_weight = min_weight
        self.max_width = max_width

    def detect(self, frame: Any) -> list[tuple[Box, float]]:
        scale = min(1.0, self.max_width / frame.shape[1])
        small = cv2.resize(frame, None, fx=scale, fy=scale) if scale < 1 else frame
        rects, weights = self.hog.detectMultiScale(small, winStride=(8, 8), padding=(8, 8), scale=1.05)
        found = []
        for (x, y, w, h), weight in zip(rects, weights, strict=False):
            if float(weight) >= self.min_weight:
                found.append(
                    (Box(int(x / scale), int(y / scale), int(w / scale), int(h / scale)), float(weight))
                )
        return found


def in_zone(box: Box, zone: dict[str, Any], width: int, height: int, min_overlap: float = 0.3) -> bool:
    """A box is in a zone (normalised x, y, w, h) when at least ``min_overlap`` of it lies inside."""
    zx, zy = zone["x"] * width, zone["y"] * height
    zw, zh = zone["w"] * width, zone["h"] * height
    ix = max(0.0, min(box.x + box.w, zx + zw) - max(box.x, zx))
    iy = max(0.0, min(box.y + box.h, zy + zh) - max(box.y, zy))
    return box.area > 0 and (ix * iy) / box.area >= min_overlap


def blur_boxes(frame: Any, boxes: list[Box]) -> Any:
    """Return a copy with every box pixelated beyond recognition."""
    out = frame.copy()
    for b in boxes:
        x0, y0 = max(0, b.x), max(0, b.y)
        x1, y1 = min(out.shape[1], b.x + b.w), min(out.shape[0], b.y + b.h)
        if x1 - x0 < 2 or y1 - y0 < 2:
            continue
        region = out[y0:y1, x0:x1]
        tiny = cv2.resize(
            region, (max(1, (x1 - x0) // 16), max(1, (y1 - y0) // 16)), interpolation=cv2.INTER_LINEAR
        )
        out[y0:y1, x0:x1] = cv2.resize(tiny, (x1 - x0, y1 - y0), interpolation=cv2.INTER_NEAREST)
    return out


def encode_jpeg(frame: Any, max_width: int = 960, quality: int = 70) -> bytes:
    scale = min(1.0, max_width / frame.shape[1])
    if scale < 1:
        frame = cv2.resize(frame, None, fx=scale, fy=scale)
    ok, buf = cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, quality])
    if not ok:
        raise RuntimeError("JPEG encoding failed")
    return bytes(buf.tobytes())


@dataclass
class Cooldown:
    seconds: float
    clock: Callable[[], float] = time.monotonic
    last: dict[str, float] = field(default_factory=dict)

    def allow(self, key: str) -> bool:
        current = self.clock()
        if key in self.last and current - self.last[key] < self.seconds:
            return False
        self.last[key] = current
        return True


class CameraMonitor:
    """Turns frames into detections and reports them; settings come from the console."""

    def __init__(
        self,
        client: Any,
        camera_key: str,
        name: str | None = None,
        *,
        motion: MotionDetector | None = None,
        people: PersonDetector | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.client = client
        self.camera_key = camera_key
        self.name = name
        self.motion = motion or MotionDetector()
        self.people = people or PersonDetector()
        self.clock = clock
        self.config: dict[str, Any] = {
            "detection_enabled": False,
            "zones": [],
            "snapshots": False,
            "blur_people": True,
            "cooldown_seconds": 30,
        }
        self.cooldown = Cooldown(30, clock)

    def apply_config(self, config: dict[str, Any]) -> None:
        self.config = {**self.config, **config}
        self.cooldown.seconds = float(self.config.get("cooldown_seconds") or 0)

    def refresh_config(self) -> None:
        self.apply_config(self.client.vision_config(self.camera_key, self.name))

    def analyse(self, frame: Any) -> tuple[list[Detection], list[Box]]:
        """Pure analysis of one frame: detections (after cooldown) and the person boxes found."""
        if not self.config.get("detection_enabled"):
            return [], []
        moving = self.motion.detect(frame)
        if not moving:
            return [], []
        found: list[Detection] = [Detection("motion", objects=len(moving))]
        people = self.people.detect(frame)
        boxes = [b for b, _ in people]
        if people:
            found.append(
                Detection("person", confidence=round(max(w for _, w in people), 2), objects=len(people))
            )
        height, width = frame.shape[:2]
        for zone in self.config.get("zones") or []:
            inside = [b for b in boxes if in_zone(b, zone, width, height)]
            if inside:
                found.append(
                    Detection(
                        "zone_intrusion",
                        zone=zone["name"],
                        objects=len(inside),
                        confidence=found[-1].confidence if people else None,
                    )
                )
        return [d for d in found if self.cooldown.allow(f"{d.type}:{d.zone or ''}")], boxes

    def handle(self, frame: Any) -> dict[str, Any] | None:
        detections, boxes = self.analyse(frame)
        if not detections:
            return None
        payload: dict[str, Any] = {
            "camera_key": self.camera_key,
            "detections": [d.as_dict() for d in detections],
        }
        if self.name:
            payload["name"] = self.name
        if self.config.get("snapshots"):
            image = blur_boxes(frame, boxes) if self.config.get("blur_people", True) else frame
            payload["snapshot_base64"] = base64.b64encode(encode_jpeg(image)).decode("ascii")
        result = self.client.send_detections(payload)
        if isinstance(result, dict) and isinstance(result.get("config"), dict):
            self.apply_config(result["config"])
        return result

    def run(
        self, source: str | int, fps: float = 2.0, config_every: float = 60.0
    ) -> None:  # pragma: no cover
        capture = cv2.VideoCapture(source)
        if not capture.isOpened():
            raise RuntimeError("cannot open the camera source")
        self.refresh_config()
        next_config = self.clock() + config_every
        interval = 1.0 / max(0.2, fps)
        log.info(
            "watching camera %s (detection %s)",
            self.camera_key,
            "on" if self.config["detection_enabled"] else "off",
        )
        try:
            while True:
                started = self.clock()
                ok, frame = capture.read()
                if not ok:
                    log.warning("no frame from the camera; retrying in 5 s")
                    time.sleep(5)
                    continue
                try:
                    if self.clock() >= next_config:
                        self.refresh_config()
                        next_config = self.clock() + config_every
                    self.handle(frame)
                except Exception as exc:  # keep watching on transient API errors
                    log.warning("could not report detections: %s", exc)
                time.sleep(max(0.0, interval - (self.clock() - started)))
        finally:
            capture.release()
